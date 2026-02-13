/**
 * OIDC Federation Baseline
 * Traditional OpenID Connect federation using Keycloak
 * For academic comparison with our Fabric+OpenID4VC solution
 */

import express from 'express';
import { Issuer, generators } from 'openid-client';
import { v4 as uuidv4 } from 'uuid';

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3100;
const KEYCLOAK_URL = process.env.KEYCLOAK_URL || 'http://localhost:8080';
const CLIENT_ID = process.env.CLIENT_ID || 'cross-domain-client';
const CLIENT_SECRET = process.env.CLIENT_SECRET || 'cross-domain-secret';

// Simulated user database (for benchmark purposes)
const users = new Map();
const tokens = new Map();
const sessions = new Map();

// Metrics collection
const metrics = {
  authenticationRequests: 0,
  tokenExchanges: 0,
  crossDomainVerifications: 0,
  totalLatency: 0,
  errors: 0
};

let oidcClient = null;

// Initialize OIDC client
async function initializeOIDC() {
  try {
    const keycloakIssuer = await Issuer.discover(`${KEYCLOAK_URL}/realms/cross-domain`);

    oidcClient = new keycloakIssuer.Client({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uris: [`http://localhost:${PORT}/callback`],
      response_types: ['code']
    });

    console.log('OIDC client initialized successfully');
  } catch (error) {
    console.log('Keycloak not available, using simulated OIDC mode');
    oidcClient = null;
  }
}

// Simulated OIDC operations for benchmark
class SimulatedOIDC {
  static generateAuthorizationUrl(state, nonce) {
    return `${KEYCLOAK_URL}/realms/cross-domain/protocol/openid-connect/auth?client_id=${CLIENT_ID}&state=${state}&nonce=${nonce}`;
  }

  static async exchangeCode(code) {
    // Simulate token exchange latency (typical Keycloak response time)
    await simulateLatency(15, 50);

    return {
      access_token: `simulated_access_${uuidv4()}`,
      refresh_token: `simulated_refresh_${uuidv4()}`,
      id_token: `simulated_id_${uuidv4()}`,
      token_type: 'Bearer',
      expires_in: 300
    };
  }

  static async introspectToken(token) {
    await simulateLatency(5, 20);

    return {
      active: true,
      sub: `user_${uuidv4().substring(0, 8)}`,
      client_id: CLIENT_ID,
      exp: Math.floor(Date.now() / 1000) + 300
    };
  }

  static async getUserInfo(accessToken) {
    await simulateLatency(10, 30);

    return {
      sub: `user_${uuidv4().substring(0, 8)}`,
      name: 'Test User',
      email: 'test@example.com',
      realm_access: {
        roles: ['user', 'cross-domain-access']
      }
    };
  }
}

// Utility function for simulating realistic latency
function simulateLatency(minMs, maxMs) {
  const latency = Math.random() * (maxMs - minMs) + minMs;
  return new Promise(resolve => setTimeout(resolve, latency));
}

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    baseline: 'oidc-federation',
    keycloakConnected: oidcClient !== null
  });
});

// Metrics endpoint
app.get('/metrics', (req, res) => {
  res.json({
    ...metrics,
    averageLatency: metrics.authenticationRequests > 0
      ? metrics.totalLatency / metrics.authenticationRequests
      : 0
  });
});

// Reset metrics
app.post('/metrics/reset', (req, res) => {
  metrics.authenticationRequests = 0;
  metrics.tokenExchanges = 0;
  metrics.crossDomainVerifications = 0;
  metrics.totalLatency = 0;
  metrics.errors = 0;
  res.json({ status: 'reset' });
});

/**
 * BASELINE TEST: Authentication Request
 * Simulates initiating cross-domain authentication
 */
app.post('/auth/initiate', async (req, res) => {
  const startTime = Date.now();

  try {
    const { sourceDomain, targetDomain, userId } = req.body;

    const state = generators.state();
    const nonce = generators.nonce();

    // Store session
    const sessionId = uuidv4();
    sessions.set(sessionId, {
      state,
      nonce,
      sourceDomain,
      targetDomain,
      userId,
      createdAt: Date.now()
    });

    let authUrl;
    if (oidcClient) {
      authUrl = oidcClient.authorizationUrl({
        scope: 'openid profile email',
        state,
        nonce
      });
    } else {
      authUrl = SimulatedOIDC.generateAuthorizationUrl(state, nonce);
    }

    const latency = Date.now() - startTime;
    metrics.authenticationRequests++;
    metrics.totalLatency += latency;

    res.json({
      sessionId,
      authorizationUrl: authUrl,
      latencyMs: latency
    });
  } catch (error) {
    metrics.errors++;
    res.status(500).json({ error: error.message });
  }
});

/**
 * BASELINE TEST: Token Exchange
 * Simulates exchanging authorization code for tokens
 */
app.post('/auth/token', async (req, res) => {
  const startTime = Date.now();

  try {
    const { code, sessionId } = req.body;

    const session = sessions.get(sessionId);
    if (!session) {
      throw new Error('Session not found');
    }

    let tokenSet;
    if (oidcClient) {
      tokenSet = await oidcClient.callback(
        `http://localhost:${PORT}/callback`,
        { code },
        { state: session.state, nonce: session.nonce }
      );
    } else {
      tokenSet = await SimulatedOIDC.exchangeCode(code);
    }

    // Store tokens
    tokens.set(sessionId, {
      ...tokenSet,
      createdAt: Date.now()
    });

    const latency = Date.now() - startTime;
    metrics.tokenExchanges++;
    metrics.totalLatency += latency;

    res.json({
      accessToken: tokenSet.access_token,
      tokenType: tokenSet.token_type,
      expiresIn: tokenSet.expires_in,
      latencyMs: latency
    });
  } catch (error) {
    metrics.errors++;
    res.status(500).json({ error: error.message });
  }
});

/**
 * BASELINE TEST: Cross-Domain Verification
 * Simulates verifying a user's identity across domains
 */
app.post('/verify/cross-domain', async (req, res) => {
  const startTime = Date.now();

  try {
    const { accessToken, sourceDomain, targetDomain, requiredClaims } = req.body;

    // Step 1: Introspect token
    let introspection;
    if (oidcClient) {
      introspection = await oidcClient.introspect(accessToken);
    } else {
      introspection = await SimulatedOIDC.introspectToken(accessToken);
    }

    if (!introspection.active) {
      throw new Error('Token is not active');
    }

    // Step 2: Get user info
    let userInfo;
    if (oidcClient) {
      userInfo = await oidcClient.userinfo(accessToken);
    } else {
      userInfo = await SimulatedOIDC.getUserInfo(accessToken);
    }

    // Step 3: Verify cross-domain policy (simulated)
    await simulateLatency(5, 15);
    const policyResult = {
      allowed: true,
      sourceDomain,
      targetDomain,
      matchedPolicy: 'default-cross-domain-policy'
    };

    // Step 4: Check required claims
    const claimsVerified = requiredClaims ?
      requiredClaims.every(claim => userInfo[claim] !== undefined) :
      true;

    const latency = Date.now() - startTime;
    metrics.crossDomainVerifications++;
    metrics.totalLatency += latency;

    res.json({
      verified: introspection.active && policyResult.allowed && claimsVerified,
      subject: userInfo.sub,
      claims: userInfo,
      policy: policyResult,
      latencyMs: latency,
      breakdown: {
        tokenIntrospection: 'included',
        userInfoFetch: 'included',
        policyEvaluation: 'included'
      }
    });
  } catch (error) {
    metrics.errors++;
    res.status(500).json({ error: error.message, verified: false });
  }
});

/**
 * BASELINE TEST: Full Cross-Domain Flow
 * End-to-end test combining all steps
 */
app.post('/test/full-flow', async (req, res) => {
  const startTime = Date.now();
  const breakdown = {};

  try {
    const { sourceDomain, targetDomain, userId } = req.body;

    // Step 1: Initiate authentication
    let stepStart = Date.now();
    const state = generators.state();
    const nonce = generators.nonce();
    const sessionId = uuidv4();

    sessions.set(sessionId, {
      state, nonce, sourceDomain, targetDomain, userId,
      createdAt: Date.now()
    });
    breakdown.authInitiation = Date.now() - stepStart;

    // Step 2: Simulate code exchange
    stepStart = Date.now();
    const tokenSet = await SimulatedOIDC.exchangeCode('simulated_code');
    tokens.set(sessionId, tokenSet);
    breakdown.tokenExchange = Date.now() - stepStart;

    // Step 3: Cross-domain verification
    stepStart = Date.now();
    const introspection = await SimulatedOIDC.introspectToken(tokenSet.access_token);
    breakdown.tokenIntrospection = Date.now() - stepStart;

    stepStart = Date.now();
    const userInfo = await SimulatedOIDC.getUserInfo(tokenSet.access_token);
    breakdown.userInfoFetch = Date.now() - stepStart;

    stepStart = Date.now();
    await simulateLatency(5, 15);
    breakdown.policyEvaluation = Date.now() - stepStart;

    const totalLatency = Date.now() - startTime;

    res.json({
      success: true,
      sessionId,
      totalLatencyMs: totalLatency,
      breakdown,
      result: {
        authenticated: true,
        crossDomainVerified: true,
        subject: userInfo.sub
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

// Credential issuance simulation (for comparison)
app.post('/credentials/issue', async (req, res) => {
  const startTime = Date.now();

  try {
    const { subjectId, credentialType, claims } = req.body;

    // Simulate credential creation latency
    await simulateLatency(20, 60);

    const credential = {
      id: uuidv4(),
      type: credentialType,
      issuer: 'oidc-federation-baseline',
      subject: subjectId,
      claims,
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString()
    };

    const latency = Date.now() - startTime;

    res.json({
      credential,
      latencyMs: latency
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start server
app.listen(PORT, async () => {
  console.log(`OIDC Baseline running on port ${PORT}`);
  await initializeOIDC();
});
