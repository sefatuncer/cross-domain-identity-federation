/**
 * Simulated Hyperledger Indy/Aries Baseline
 * Simulates Indy-style SSI operations for academic comparison
 *
 * Note: This is a simulation that mimics Indy's behavior and latency patterns
 * For a real comparison, you would use actual Indy SDK
 */

import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import { sha256 } from 'js-sha256';
import fs from 'fs';

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3300;
const GENESIS_PATH = process.env.GENESIS_PATH || './genesis.json';

// Load genesis configuration
let genesisConfig;
try {
  genesisConfig = JSON.parse(fs.readFileSync(GENESIS_PATH, 'utf8'));
} catch {
  genesisConfig = {
    network: 'simulated',
    nodes: [],
    trustAnchors: []
  };
}

// Simulated ledger state
const ledger = {
  dids: new Map(),
  schemas: new Map(),
  credentialDefinitions: new Map(),
  revocationRegistries: new Map(),
  credentials: new Map()
};

// Wallet simulation
const wallets = new Map();

// Metrics
const metrics = {
  didCreation: 0,
  schemaCreation: 0,
  credDefCreation: 0,
  credentialIssuance: 0,
  credentialVerification: 0,
  proofPresentation: 0,
  ledgerReads: 0,
  ledgerWrites: 0,
  totalLatency: 0,
  errors: 0
};

// Simulate realistic Indy latency based on operation type
function simulateIndyLatency(operation) {
  const latencyRanges = {
    // Ledger write operations (consensus required)
    ledgerWrite: { min: 100, max: 300 },
    // Ledger read operations
    ledgerRead: { min: 20, max: 80 },
    // Local wallet operations
    walletOperation: { min: 5, max: 20 },
    // Cryptographic operations
    cryptoOperation: { min: 10, max: 50 },
    // Proof generation (complex crypto)
    proofGeneration: { min: 50, max: 200 },
    // Proof verification
    proofVerification: { min: 30, max: 100 }
  };

  const range = latencyRanges[operation] || { min: 10, max: 50 };
  const latency = Math.random() * (range.max - range.min) + range.min;
  return new Promise(resolve => setTimeout(resolve, latency));
}

// Generate simulated DID
function generateDID(method = 'indy') {
  const seed = uuidv4().replace(/-/g, '').substring(0, 32);
  const verkey = sha256(seed).substring(0, 44);
  return {
    did: `did:${method}:simulated:${uuidv4().substring(0, 22)}`,
    verkey: `~${verkey}`,
    seed
  };
}

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    baseline: 'indy-simulated',
    network: genesisConfig.network,
    nodeCount: genesisConfig.nodes.length
  });
});

// Metrics endpoint
app.get('/metrics', (req, res) => {
  const totalOps = metrics.didCreation + metrics.credentialIssuance +
    metrics.credentialVerification + metrics.proofPresentation;
  res.json({
    ...metrics,
    averageLatency: totalOps > 0 ? metrics.totalLatency / totalOps : 0
  });
});

// Reset metrics
app.post('/metrics/reset', (req, res) => {
  Object.keys(metrics).forEach(key => metrics[key] = 0);
  res.json({ status: 'reset' });
});

/**
 * BASELINE TEST: Create DID
 * Simulates Indy DID creation and ledger registration
 */
app.post('/did/create', async (req, res) => {
  const startTime = Date.now();
  const breakdown = {};

  try {
    const { alias, role = 'ENDORSER' } = req.body;

    // Step 1: Generate DID locally
    let stepStart = Date.now();
    await simulateIndyLatency('cryptoOperation');
    const didInfo = generateDID();
    breakdown.keyGeneration = Date.now() - stepStart;

    // Step 2: Write to ledger (consensus)
    stepStart = Date.now();
    await simulateIndyLatency('ledgerWrite');
    ledger.dids.set(didInfo.did, {
      ...didInfo,
      alias,
      role,
      createdAt: Date.now()
    });
    breakdown.ledgerWrite = Date.now() - stepStart;
    metrics.ledgerWrites++;

    const latency = Date.now() - startTime;
    metrics.didCreation++;
    metrics.totalLatency += latency;

    res.json({
      did: didInfo.did,
      verkey: didInfo.verkey,
      latencyMs: latency,
      breakdown
    });
  } catch (error) {
    metrics.errors++;
    res.status(500).json({ error: error.message });
  }
});

/**
 * BASELINE TEST: Create Schema
 * Simulates Indy schema creation
 */
app.post('/schema/create', async (req, res) => {
  const startTime = Date.now();
  const breakdown = {};

  try {
    const { issuerDid, name, version, attributes } = req.body;

    // Step 1: Build schema
    let stepStart = Date.now();
    await simulateIndyLatency('walletOperation');
    const schemaId = `${issuerDid}:2:${name}:${version}`;
    const schema = {
      id: schemaId,
      name,
      version,
      attrNames: attributes,
      seqNo: ledger.schemas.size + 1
    };
    breakdown.schemaBuild = Date.now() - stepStart;

    // Step 2: Write to ledger
    stepStart = Date.now();
    await simulateIndyLatency('ledgerWrite');
    ledger.schemas.set(schemaId, schema);
    breakdown.ledgerWrite = Date.now() - stepStart;
    metrics.ledgerWrites++;

    const latency = Date.now() - startTime;
    metrics.schemaCreation++;
    metrics.totalLatency += latency;

    res.json({
      schemaId,
      schema,
      latencyMs: latency,
      breakdown
    });
  } catch (error) {
    metrics.errors++;
    res.status(500).json({ error: error.message });
  }
});

/**
 * BASELINE TEST: Create Credential Definition
 * Simulates Indy credential definition creation
 */
app.post('/creddef/create', async (req, res) => {
  const startTime = Date.now();
  const breakdown = {};

  try {
    const { issuerDid, schemaId, tag = 'default', supportRevocation = true } = req.body;

    // Step 1: Generate credential definition keys (heavy crypto)
    let stepStart = Date.now();
    await simulateIndyLatency('cryptoOperation');
    await simulateIndyLatency('cryptoOperation'); // CL signatures are complex
    const credDefId = `${issuerDid}:3:CL:${schemaId}:${tag}`;
    breakdown.keyGeneration = Date.now() - stepStart;

    // Step 2: Write to ledger
    stepStart = Date.now();
    await simulateIndyLatency('ledgerWrite');
    ledger.credentialDefinitions.set(credDefId, {
      id: credDefId,
      schemaId,
      issuerDid,
      tag,
      supportRevocation,
      seqNo: ledger.credentialDefinitions.size + 1
    });
    breakdown.ledgerWrite = Date.now() - stepStart;
    metrics.ledgerWrites++;

    // Step 3: Create revocation registry if needed
    if (supportRevocation) {
      stepStart = Date.now();
      await simulateIndyLatency('ledgerWrite');
      const revRegId = `${issuerDid}:4:${credDefId}:CL_ACCUM:default`;
      ledger.revocationRegistries.set(revRegId, {
        id: revRegId,
        credDefId,
        maxCredNum: 1000,
        currentAccumulator: sha256(uuidv4())
      });
      breakdown.revocationRegistry = Date.now() - stepStart;
      metrics.ledgerWrites++;
    }

    const latency = Date.now() - startTime;
    metrics.credDefCreation++;
    metrics.totalLatency += latency;

    res.json({
      credDefId,
      latencyMs: latency,
      breakdown
    });
  } catch (error) {
    metrics.errors++;
    res.status(500).json({ error: error.message });
  }
});

/**
 * BASELINE TEST: Issue Credential
 * Simulates Indy credential issuance with CL signatures
 */
app.post('/credentials/issue', async (req, res) => {
  const startTime = Date.now();
  const breakdown = {};

  try {
    const { credDefId, holderDid, attributes } = req.body;

    // Step 1: Fetch credential definition from ledger
    let stepStart = Date.now();
    await simulateIndyLatency('ledgerRead');
    const credDef = ledger.credentialDefinitions.get(credDefId);
    if (!credDef) {
      throw new Error('Credential definition not found');
    }
    breakdown.credDefLookup = Date.now() - stepStart;
    metrics.ledgerReads++;

    // Step 2: Create credential offer
    stepStart = Date.now();
    await simulateIndyLatency('cryptoOperation');
    const credentialOffer = {
      schemaId: credDef.schemaId,
      credDefId,
      nonce: uuidv4()
    };
    breakdown.offerCreation = Date.now() - stepStart;

    // Step 3: Process credential request (holder side - simulated)
    stepStart = Date.now();
    await simulateIndyLatency('cryptoOperation');
    const credentialRequest = {
      credDefId,
      blindedMs: sha256(holderDid + uuidv4()),
      nonce: uuidv4()
    };
    breakdown.requestProcessing = Date.now() - stepStart;

    // Step 4: Create credential (CL signature - heavy crypto)
    stepStart = Date.now();
    await simulateIndyLatency('cryptoOperation');
    await simulateIndyLatency('cryptoOperation');
    const credentialId = uuidv4();
    const credential = {
      id: credentialId,
      schemaId: credDef.schemaId,
      credDefId,
      signature: sha256(JSON.stringify(attributes) + uuidv4()),
      signatureCorrectnessProof: sha256(uuidv4()),
      values: attributes,
      revRegId: credDef.supportRevocation ?
        `${credDef.issuerDid}:4:${credDefId}:CL_ACCUM:default` : null
    };
    breakdown.signatureCreation = Date.now() - stepStart;

    // Step 5: Store in wallet
    stepStart = Date.now();
    await simulateIndyLatency('walletOperation');
    ledger.credentials.set(credentialId, credential);
    breakdown.walletStorage = Date.now() - stepStart;

    const latency = Date.now() - startTime;
    metrics.credentialIssuance++;
    metrics.totalLatency += latency;

    res.json({
      credentialId,
      credential: {
        schemaId: credential.schemaId,
        credDefId: credential.credDefId,
        values: credential.values
      },
      latencyMs: latency,
      breakdown
    });
  } catch (error) {
    metrics.errors++;
    res.status(500).json({ error: error.message });
  }
});

/**
 * BASELINE TEST: Verify Credential (Proof Presentation)
 * Simulates Indy zero-knowledge proof presentation and verification
 */
app.post('/credentials/verify', async (req, res) => {
  const startTime = Date.now();
  const breakdown = {};

  try {
    const { credentialId, requestedAttributes, predicates } = req.body;

    // Step 1: Fetch credential from wallet
    let stepStart = Date.now();
    await simulateIndyLatency('walletOperation');
    const credential = ledger.credentials.get(credentialId);
    if (!credential) {
      throw new Error('Credential not found');
    }
    breakdown.credentialFetch = Date.now() - stepStart;

    // Step 2: Fetch credential definition from ledger
    stepStart = Date.now();
    await simulateIndyLatency('ledgerRead');
    const credDef = ledger.credentialDefinitions.get(credential.credDefId);
    breakdown.credDefLookup = Date.now() - stepStart;
    metrics.ledgerReads++;

    // Step 3: Fetch schema from ledger
    stepStart = Date.now();
    await simulateIndyLatency('ledgerRead');
    const schema = ledger.schemas.get(credential.schemaId);
    breakdown.schemaLookup = Date.now() - stepStart;
    metrics.ledgerReads++;

    // Step 4: Generate proof (heavy ZKP crypto)
    stepStart = Date.now();
    await simulateIndyLatency('proofGeneration');
    const proof = {
      requestedProof: {
        revealedAttrs: requestedAttributes || Object.keys(credential.values),
        selfAttestedAttrs: {},
        predicates: predicates || []
      },
      proof: sha256(JSON.stringify(credential) + uuidv4()),
      identifiers: [{
        schemaId: credential.schemaId,
        credDefId: credential.credDefId,
        revRegId: credential.revRegId
      }]
    };
    breakdown.proofGeneration = Date.now() - stepStart;

    // Step 5: Verify proof
    stepStart = Date.now();
    await simulateIndyLatency('proofVerification');
    const verified = true; // Simulated verification success
    breakdown.proofVerification = Date.now() - stepStart;

    // Step 6: Check revocation status (if applicable)
    if (credential.revRegId) {
      stepStart = Date.now();
      await simulateIndyLatency('ledgerRead');
      const revReg = ledger.revocationRegistries.get(credential.revRegId);
      breakdown.revocationCheck = Date.now() - stepStart;
      metrics.ledgerReads++;
    }

    const latency = Date.now() - startTime;
    metrics.credentialVerification++;
    metrics.proofPresentation++;
    metrics.totalLatency += latency;

    res.json({
      verified,
      proof: {
        revealedAttributes: credential.values,
        credDefId: credential.credDefId,
        schemaId: credential.schemaId
      },
      latencyMs: latency,
      breakdown
    });
  } catch (error) {
    metrics.errors++;
    res.status(500).json({ error: error.message, verified: false });
  }
});

/**
 * BASELINE TEST: Cross-Domain Verification
 * Simulates verifying a credential from one domain in another
 */
app.post('/verify/cross-domain', async (req, res) => {
  const startTime = Date.now();
  const breakdown = {};

  try {
    const { credentialId, sourceDomain, targetDomain, proofRequest } = req.body;

    // Step 1: Fetch credential
    let stepStart = Date.now();
    await simulateIndyLatency('walletOperation');
    const credential = ledger.credentials.get(credentialId);
    if (!credential) {
      throw new Error('Credential not found');
    }
    breakdown.credentialFetch = Date.now() - stepStart;

    // Step 2: Fetch all ledger entities
    stepStart = Date.now();
    await simulateIndyLatency('ledgerRead');
    const credDef = ledger.credentialDefinitions.get(credential.credDefId);
    breakdown.credDefLookup = Date.now() - stepStart;
    metrics.ledgerReads++;

    stepStart = Date.now();
    await simulateIndyLatency('ledgerRead');
    const schema = ledger.schemas.get(credential.schemaId);
    breakdown.schemaLookup = Date.now() - stepStart;
    metrics.ledgerReads++;

    // Step 3: Verify issuer DID on ledger
    stepStart = Date.now();
    await simulateIndyLatency('ledgerRead');
    const issuerDid = ledger.dids.get(credDef.issuerDid);
    const issuerTrusted = issuerDid !== undefined;
    breakdown.issuerVerification = Date.now() - stepStart;
    metrics.ledgerReads++;

    // Step 4: Generate ZKP proof
    stepStart = Date.now();
    await simulateIndyLatency('proofGeneration');
    breakdown.proofGeneration = Date.now() - stepStart;

    // Step 5: Verify ZKP proof
    stepStart = Date.now();
    await simulateIndyLatency('proofVerification');
    breakdown.proofVerification = Date.now() - stepStart;

    // Step 6: Check revocation
    if (credential.revRegId) {
      stepStart = Date.now();
      await simulateIndyLatency('ledgerRead');
      breakdown.revocationCheck = Date.now() - stepStart;
      metrics.ledgerReads++;
    }

    // Step 7: Cross-domain policy check (simulated - Indy doesn't have this natively)
    stepStart = Date.now();
    await simulateIndyLatency('walletOperation');
    const policyAllowed = true; // Simulated - in real Indy, this would be application logic
    breakdown.policyCheck = Date.now() - stepStart;

    const latency = Date.now() - startTime;
    metrics.credentialVerification++;
    metrics.totalLatency += latency;

    res.json({
      verified: issuerTrusted && policyAllowed,
      credential: {
        schemaId: credential.schemaId,
        credDefId: credential.credDefId,
        values: credential.values
      },
      validations: {
        proofValid: true,
        issuerTrusted,
        notRevoked: true,
        policyAllowed
      },
      latencyMs: latency,
      breakdown
    });
  } catch (error) {
    metrics.errors++;
    res.status(500).json({ error: error.message, verified: false });
  }
});

/**
 * BASELINE TEST: Full Flow
 * Complete flow: DID creation → Schema → CredDef → Issue → Verify
 */
app.post('/test/full-flow', async (req, res) => {
  const startTime = Date.now();
  const breakdown = {};

  try {
    const { sourceDomain, targetDomain, credentialType, attributes } = req.body;

    // Step 1: Create issuer DID
    let stepStart = Date.now();
    await simulateIndyLatency('cryptoOperation');
    await simulateIndyLatency('ledgerWrite');
    const issuerDid = generateDID();
    ledger.dids.set(issuerDid.did, { ...issuerDid, domain: sourceDomain });
    breakdown.didCreation = Date.now() - stepStart;

    // Step 2: Create schema
    stepStart = Date.now();
    await simulateIndyLatency('walletOperation');
    await simulateIndyLatency('ledgerWrite');
    const schemaId = `${issuerDid.did}:2:${credentialType}:1.0`;
    ledger.schemas.set(schemaId, {
      id: schemaId,
      attrNames: Object.keys(attributes || { name: '', value: '' })
    });
    breakdown.schemaCreation = Date.now() - stepStart;

    // Step 3: Create credential definition
    stepStart = Date.now();
    await simulateIndyLatency('cryptoOperation');
    await simulateIndyLatency('cryptoOperation');
    await simulateIndyLatency('ledgerWrite');
    const credDefId = `${issuerDid.did}:3:CL:${schemaId}:default`;
    ledger.credentialDefinitions.set(credDefId, {
      id: credDefId,
      schemaId,
      issuerDid: issuerDid.did
    });
    breakdown.credDefCreation = Date.now() - stepStart;

    // Step 4: Issue credential
    stepStart = Date.now();
    await simulateIndyLatency('cryptoOperation');
    await simulateIndyLatency('cryptoOperation');
    const credentialId = uuidv4();
    ledger.credentials.set(credentialId, {
      id: credentialId,
      schemaId,
      credDefId,
      values: attributes || {}
    });
    breakdown.credentialIssuance = Date.now() - stepStart;

    // Step 5: Cross-domain verification
    stepStart = Date.now();
    await simulateIndyLatency('ledgerRead');
    await simulateIndyLatency('ledgerRead');
    await simulateIndyLatency('ledgerRead');
    await simulateIndyLatency('proofGeneration');
    await simulateIndyLatency('proofVerification');
    breakdown.crossDomainVerification = Date.now() - stepStart;

    const totalLatency = Date.now() - startTime;

    res.json({
      success: true,
      credentialId,
      totalLatencyMs: totalLatency,
      breakdown,
      result: {
        didCreated: issuerDid.did,
        schemaCreated: schemaId,
        credDefCreated: credDefId,
        credentialIssued: credentialId,
        crossDomainVerified: true
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

// Get ledger stats
app.get('/ledger/stats', (req, res) => {
  res.json({
    dids: ledger.dids.size,
    schemas: ledger.schemas.size,
    credentialDefinitions: ledger.credentialDefinitions.size,
    revocationRegistries: ledger.revocationRegistries.size,
    credentials: ledger.credentials.size
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Indy Baseline (Simulated) running on port ${PORT}`);
  console.log(`Network: ${genesisConfig.network}`);
  console.log(`Nodes: ${genesisConfig.nodes.length}`);
});
