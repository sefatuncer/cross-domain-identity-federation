/**
 * Centralized Identity System Baseline
 * Traditional database-backed identity management
 * For academic comparison with our Fabric+OpenID4VC solution
 */

import express from 'express';
import pg from 'pg';
import { createClient } from 'redis';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';

const { Pool } = pg;

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3200;
const JWT_SECRET = process.env.JWT_SECRET || 'centralized-jwt-secret-key-for-testing';
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://identity:identity_password@localhost:5433/identity_central';
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';

// Database connection
const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Redis connection
let redisClient;

// Metrics collection
const metrics = {
  credentialIssuance: 0,
  credentialVerification: 0,
  crossDomainVerification: 0,
  policyEvaluation: 0,
  totalLatency: 0,
  cacheHits: 0,
  cacheMisses: 0,
  errors: 0
};

// Initialize connections
async function initialize() {
  try {
    // Test database connection
    await pool.query('SELECT 1');
    console.log('Database connected');

    // Connect to Redis
    redisClient = createClient({ url: REDIS_URL });
    redisClient.on('error', err => console.log('Redis error:', err));
    await redisClient.connect();
    console.log('Redis connected');
  } catch (error) {
    console.log('Running in standalone mode (no external dependencies)');
    redisClient = null;
  }
}

// Cache helper functions
async function cacheGet(key) {
  if (!redisClient) return null;
  try {
    const value = await redisClient.get(key);
    if (value) {
      metrics.cacheHits++;
      return JSON.parse(value);
    }
    metrics.cacheMisses++;
    return null;
  } catch {
    return null;
  }
}

async function cacheSet(key, value, ttlSeconds = 300) {
  if (!redisClient) return;
  try {
    await redisClient.setEx(key, ttlSeconds, JSON.stringify(value));
  } catch {
    // Ignore cache errors
  }
}

// Health check
app.get('/health', async (req, res) => {
  let dbHealthy = false;
  let cacheHealthy = false;

  try {
    await pool.query('SELECT 1');
    dbHealthy = true;
  } catch {}

  try {
    if (redisClient) {
      await redisClient.ping();
      cacheHealthy = true;
    }
  } catch {}

  res.json({
    status: dbHealthy ? 'healthy' : 'degraded',
    baseline: 'centralized',
    database: dbHealthy,
    cache: cacheHealthy
  });
});

// Metrics endpoint
app.get('/metrics', (req, res) => {
  const totalOps = metrics.credentialIssuance + metrics.credentialVerification + metrics.crossDomainVerification;
  res.json({
    ...metrics,
    averageLatency: totalOps > 0 ? metrics.totalLatency / totalOps : 0,
    cacheHitRate: (metrics.cacheHits + metrics.cacheMisses) > 0
      ? metrics.cacheHits / (metrics.cacheHits + metrics.cacheMisses)
      : 0
  });
});

// Reset metrics
app.post('/metrics/reset', (req, res) => {
  Object.keys(metrics).forEach(key => metrics[key] = 0);
  res.json({ status: 'reset' });
});

/**
 * BASELINE TEST: Issue Credential
 * Direct database insert with caching
 */
app.post('/credentials/issue', async (req, res) => {
  const startTime = Date.now();

  try {
    const { userId, credentialType, issuerDomain, claims, expiresInDays = 365 } = req.body;

    const credentialId = uuidv4();
    const expiresAt = new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000);

    // Use test user IDs from init.sql if no userId provided
    const testUserIds = {
      finance: '550e8400-e29b-41d4-a716-446655440000',
      healthcare: '550e8400-e29b-41d4-a716-446655440001',
      education: '550e8400-e29b-41d4-a716-446655440002'
    };
    const finalUserId = userId || testUserIds[issuerDomain] || testUserIds.finance;

    // Insert into database
    const result = await pool.query(
      `INSERT INTO credentials (id, user_id, credential_type, issuer_domain, claims, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [credentialId, finalUserId, credentialType, issuerDomain, claims, expiresAt]
    );

    const credential = result.rows[0];

    // Cache the credential
    await cacheSet(`credential:${credentialId}`, credential);

    const latency = Date.now() - startTime;
    metrics.credentialIssuance++;
    metrics.totalLatency += latency;

    res.json({
      credential: {
        id: credential.id,
        type: credential.credential_type,
        issuer: credential.issuer_domain,
        claims: credential.claims,
        issuedAt: credential.issued_at,
        expiresAt: credential.expires_at
      },
      latencyMs: latency
    });
  } catch (error) {
    metrics.errors++;
    res.status(500).json({ error: error.message });
  }
});

/**
 * BASELINE TEST: Verify Credential
 * Database lookup with caching
 */
app.post('/credentials/verify', async (req, res) => {
  const startTime = Date.now();
  const breakdown = {};

  try {
    const { credentialId, verifierDomain } = req.body;

    // Step 1: Try cache first
    let stepStart = Date.now();
    let credential = await cacheGet(`credential:${credentialId}`);
    breakdown.cacheCheck = Date.now() - stepStart;

    // Step 2: Database lookup if not cached
    if (!credential) {
      stepStart = Date.now();
      const result = await pool.query(
        'SELECT * FROM credentials WHERE id = $1',
        [credentialId]
      );
      breakdown.databaseLookup = Date.now() - stepStart;

      if (result.rows.length === 0) {
        throw new Error('Credential not found');
      }

      credential = result.rows[0];
      await cacheSet(`credential:${credentialId}`, credential);
    }

    // Step 3: Check expiration and revocation
    stepStart = Date.now();
    const isValid = !credential.revoked &&
      new Date(credential.expires_at) > new Date();
    breakdown.validationCheck = Date.now() - stepStart;

    // Step 4: Verify issuer trust
    stepStart = Date.now();
    const issuerResult = await pool.query(
      'SELECT * FROM trusted_issuers WHERE domain = $1 AND active = TRUE',
      [credential.issuer_domain]
    );
    const issuerTrusted = issuerResult.rows.length > 0;
    breakdown.issuerVerification = Date.now() - stepStart;

    // Step 5: Log verification
    stepStart = Date.now();
    const totalLatency = Date.now() - startTime;
    await pool.query(
      `INSERT INTO verification_logs (id, credential_id, verifier_domain, verification_result, latency_ms)
       VALUES ($1, $2, $3, $4, $5)`,
      [uuidv4(), credentialId, verifierDomain, isValid && issuerTrusted, totalLatency]
    );
    breakdown.auditLogging = Date.now() - stepStart;

    metrics.credentialVerification++;
    metrics.totalLatency += totalLatency;

    res.json({
      verified: isValid && issuerTrusted,
      credential: {
        id: credential.id,
        type: credential.credential_type,
        issuer: credential.issuer_domain,
        claims: credential.claims
      },
      issuerTrusted,
      latencyMs: totalLatency,
      breakdown
    });
  } catch (error) {
    metrics.errors++;
    res.status(500).json({ error: error.message, verified: false });
  }
});

/**
 * BASELINE TEST: Cross-Domain Verification
 * Full cross-domain credential verification
 */
app.post('/verify/cross-domain', async (req, res) => {
  const startTime = Date.now();
  const breakdown = {};

  try {
    const { credentialId, sourceDomain, targetDomain, requiredClaims } = req.body;

    // Step 1: Fetch credential (with cache)
    let stepStart = Date.now();
    let credential = await cacheGet(`credential:${credentialId}`);
    if (!credential) {
      const result = await pool.query(
        'SELECT * FROM credentials WHERE id = $1',
        [credentialId]
      );
      if (result.rows.length === 0) {
        throw new Error('Credential not found');
      }
      credential = result.rows[0];
      await cacheSet(`credential:${credentialId}`, credential);
    }
    breakdown.credentialFetch = Date.now() - stepStart;

    // Step 2: Verify credential validity
    stepStart = Date.now();
    const isValid = !credential.revoked &&
      new Date(credential.expires_at) > new Date();
    breakdown.validityCheck = Date.now() - stepStart;

    // Step 3: Verify issuer trust
    stepStart = Date.now();
    const issuerCacheKey = `issuer:${credential.issuer_domain}`;
    let issuer = await cacheGet(issuerCacheKey);
    if (!issuer) {
      const issuerResult = await pool.query(
        'SELECT * FROM trusted_issuers WHERE domain = $1 AND active = TRUE',
        [credential.issuer_domain]
      );
      issuer = issuerResult.rows[0] || null;
      if (issuer) await cacheSet(issuerCacheKey, issuer);
    }
    const issuerTrusted = issuer !== null;
    breakdown.issuerVerification = Date.now() - stepStart;

    // Step 4: Evaluate cross-domain policy
    stepStart = Date.now();
    const policyCacheKey = `policy:${sourceDomain}:${targetDomain}:${credential.credential_type}`;
    let policy = await cacheGet(policyCacheKey);
    if (!policy) {
      const policyResult = await pool.query(
        `SELECT * FROM cross_domain_policies
         WHERE source_domain = $1 AND target_domain = $2 AND credential_type = $3`,
        [sourceDomain, targetDomain, credential.credential_type]
      );
      policy = policyResult.rows[0] || { allowed: false };
      await cacheSet(policyCacheKey, policy);
    }
    breakdown.policyEvaluation = Date.now() - stepStart;
    metrics.policyEvaluation++;

    // Step 5: Check required claims
    stepStart = Date.now();
    let claimsVerified = true;
    if (requiredClaims && requiredClaims.length > 0) {
      claimsVerified = requiredClaims.every(claim =>
        credential.claims && credential.claims[claim] !== undefined
      );
    }
    breakdown.claimsVerification = Date.now() - stepStart;

    // Step 6: Log verification
    stepStart = Date.now();
    const totalLatency = Date.now() - startTime;
    await pool.query(
      `INSERT INTO verification_logs (id, credential_id, verifier_domain, verification_result, latency_ms)
       VALUES ($1, $2, $3, $4, $5)`,
      [uuidv4(), credentialId, targetDomain, isValid && issuerTrusted && policy.allowed && claimsVerified, totalLatency]
    );
    breakdown.auditLogging = Date.now() - stepStart;

    metrics.crossDomainVerification++;
    metrics.totalLatency += totalLatency;

    res.json({
      verified: isValid && issuerTrusted && policy.allowed && claimsVerified,
      credential: {
        id: credential.id,
        type: credential.credential_type,
        issuer: credential.issuer_domain
      },
      validations: {
        credentialValid: isValid,
        issuerTrusted,
        policyAllowed: policy.allowed,
        claimsPresent: claimsVerified
      },
      latencyMs: totalLatency,
      breakdown
    });
  } catch (error) {
    metrics.errors++;
    res.status(500).json({ error: error.message, verified: false });
  }
});

/**
 * BASELINE TEST: Full Cross-Domain Flow
 * End-to-end test: issue + verify across domains
 */
app.post('/test/full-flow', async (req, res) => {
  const startTime = Date.now();
  const breakdown = {};

  try {
    const { sourceDomain, targetDomain, credentialType, claims } = req.body;

    // Step 1: Issue credential
    let stepStart = Date.now();
    const credentialId = uuidv4();
    // Use test user from init.sql based on source domain
    const testUserIds = {
      finance: '550e8400-e29b-41d4-a716-446655440000',
      healthcare: '550e8400-e29b-41d4-a716-446655440001',
      education: '550e8400-e29b-41d4-a716-446655440002'
    };
    const userId = testUserIds[sourceDomain] || testUserIds.finance;
    const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);

    await pool.query(
      `INSERT INTO credentials (id, user_id, credential_type, issuer_domain, claims, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [credentialId, userId, credentialType, sourceDomain, claims || {}, expiresAt]
    );
    breakdown.credentialIssuance = Date.now() - stepStart;

    // Step 2: Cross-domain verification
    stepStart = Date.now();
    const policyResult = await pool.query(
      `SELECT * FROM cross_domain_policies
       WHERE source_domain = $1 AND target_domain = $2 AND credential_type = $3`,
      [sourceDomain, targetDomain, credentialType]
    );
    const policyAllowed = policyResult.rows.length > 0 && policyResult.rows[0].allowed;
    breakdown.policyEvaluation = Date.now() - stepStart;

    // Step 3: Issuer verification
    stepStart = Date.now();
    const issuerResult = await pool.query(
      'SELECT * FROM trusted_issuers WHERE domain = $1 AND active = TRUE',
      [sourceDomain]
    );
    const issuerTrusted = issuerResult.rows.length > 0;
    breakdown.issuerVerification = Date.now() - stepStart;

    // Step 4: Log verification
    stepStart = Date.now();
    const totalLatency = Date.now() - startTime;
    await pool.query(
      `INSERT INTO verification_logs (id, credential_id, verifier_domain, verification_result, latency_ms)
       VALUES ($1, $2, $3, $4, $5)`,
      [uuidv4(), credentialId, targetDomain, policyAllowed && issuerTrusted, totalLatency]
    );
    breakdown.auditLogging = Date.now() - stepStart;

    res.json({
      success: policyAllowed && issuerTrusted,
      credentialId,
      totalLatencyMs: totalLatency,
      breakdown,
      result: {
        issued: true,
        policyAllowed,
        issuerTrusted,
        crossDomainVerified: policyAllowed && issuerTrusted
      }
    });
  } catch (error) {
    metrics.errors++;
    res.status(500).json({
      success: false,
      error: error.message,
      totalLatencyMs: Date.now() - startTime
    });
  }
});

/**
 * Register trusted issuer
 */
app.post('/issuers/register', async (req, res) => {
  const startTime = Date.now();

  try {
    const { domain, name, credentialTypes, trustLevel = 1 } = req.body;

    const result = await pool.query(
      `INSERT INTO trusted_issuers (id, domain, name, credential_types, trust_level)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [uuidv4(), domain, name, credentialTypes, trustLevel]
    );

    res.json({
      issuer: result.rows[0],
      latencyMs: Date.now() - startTime
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Query issuer
 */
app.get('/issuers/:domain', async (req, res) => {
  const startTime = Date.now();

  try {
    const { domain } = req.params;

    // Try cache
    let issuer = await cacheGet(`issuer:${domain}`);
    if (!issuer) {
      const result = await pool.query(
        'SELECT * FROM trusted_issuers WHERE domain = $1',
        [domain]
      );
      issuer = result.rows[0] || null;
      if (issuer) await cacheSet(`issuer:${domain}`, issuer);
    }

    if (!issuer) {
      return res.status(404).json({ error: 'Issuer not found' });
    }

    res.json({
      issuer,
      latencyMs: Date.now() - startTime
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start server
app.listen(PORT, async () => {
  console.log(`Centralized Baseline running on port ${PORT}`);
  await initialize();
});
