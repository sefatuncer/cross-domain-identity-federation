import dotenv from 'dotenv';

dotenv.config();

export interface BridgeConfig {
  port: number;
  fabric: {
    gatewayHost: string;
    gatewayPort: number;
    channelName: string;
    chaincodeName: string;
    mspId: string;
    certificatePath: string;
    privateKeyPath: string;
    tlsCertPath: string;
    peerEndpoint: string;
  };
  openid: {
    financeIssuer: string;
    healthcareIssuer: string;
    educationIssuer: string;
    verifier: string;
  };
}

export function getConfig(): BridgeConfig {
  return {
    port: parseInt(process.env.PORT || '4000', 10),
    fabric: {
      gatewayHost: process.env.FABRIC_GATEWAY_HOST || 'localhost',
      gatewayPort: parseInt(process.env.FABRIC_GATEWAY_PORT || '7051', 10),
      channelName: process.env.FABRIC_CHANNEL_NAME || 'global-channel',
      chaincodeName: process.env.FABRIC_CHAINCODE_NAME || 'trusted-issuer-registry',
      mspId: process.env.FABRIC_MSP_ID || 'FinanceMSP',
      certificatePath: process.env.FABRIC_CERT_PATH || '/app/fabric-config/organizations/peerOrganizations/finance.crossdomain.com/users/Admin@finance.crossdomain.com/msp/signcerts/cert.pem',
      privateKeyPath: process.env.FABRIC_KEY_PATH || '/app/fabric-config/organizations/peerOrganizations/finance.crossdomain.com/users/Admin@finance.crossdomain.com/msp/keystore/priv_sk',
      tlsCertPath: process.env.FABRIC_TLS_CERT_PATH || '/app/fabric-config/organizations/peerOrganizations/finance.crossdomain.com/peers/peer0.finance.crossdomain.com/tls/ca.crt',
      peerEndpoint: process.env.FABRIC_PEER_ENDPOINT || 'peer0.finance.crossdomain.com:7051',
    },
    openid: {
      financeIssuer: process.env.OPENID_FINANCE_ISSUER || 'http://localhost:3001',
      healthcareIssuer: process.env.OPENID_HEALTHCARE_ISSUER || 'http://localhost:3002',
      educationIssuer: process.env.OPENID_EDUCATION_ISSUER || 'http://localhost:3003',
      verifier: process.env.OPENID_VERIFIER || 'http://localhost:3020',
    },
  };
}

// Chaincode names
export const CHAINCODES = {
  TRUSTED_ISSUER_REGISTRY: 'trusted-issuer-registry',
  CREDENTIAL_SCHEMA_REGISTRY: 'credential-schema-registry',
  CROSS_DOMAIN_POLICY: 'cross-domain-policy',
  PRIVACY_AUDIT: 'privacy-audit',
};

// Channel names
export const CHANNELS = {
  GLOBAL: 'global-channel',
  FINANCE: 'finance-channel',
  HEALTHCARE: 'healthcare-channel',
  EDUCATION: 'education-channel',
  CROSS_DOMAIN: 'crossdomain-channel',
};

// Domain types
export type DomainType = 'FINANCE' | 'HEALTHCARE' | 'EDUCATION';
