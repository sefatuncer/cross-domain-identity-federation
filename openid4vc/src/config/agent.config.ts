import { InitConfig, KeyDerivationMethod, LogLevel } from '@credo-ts/core';

export interface AgentConfig {
  agentType: 'issuer' | 'holder' | 'verifier';
  agentName: string;
  agentPort: number;
  agentEndpoint: string;
  walletConfig: {
    id: string;
    key: string;
    keyDerivationMethod: KeyDerivationMethod;
    storage?: {
      type: 'postgres';
      config: {
        host: string;
        port: number;
        database: string;
        username: string;
        password: string;
      };
    };
  };
  sectorType?: 'finance' | 'healthcare' | 'education';
  fabricBridgeUrl?: string;
}

export function getAgentConfig(): AgentConfig {
  const agentType = (process.env.AGENT_TYPE || 'issuer') as 'issuer' | 'holder' | 'verifier';
  const agentName = process.env.AGENT_NAME || `CrossDomain${agentType.charAt(0).toUpperCase() + agentType.slice(1)}`;
  const agentPort = parseInt(process.env.AGENT_PORT || '3001', 10);
  const agentEndpoint = process.env.AGENT_ENDPOINT || `http://localhost:${agentPort}`;
  const sectorType = process.env.SECTOR_TYPE as 'finance' | 'healthcare' | 'education' | undefined;
  const fabricBridgeUrl = process.env.FABRIC_BRIDGE_URL || 'http://localhost:4000';

  // Parse database URL if provided
  let storageConfig = undefined;
  if (process.env.DATABASE_URL) {
    const dbUrl = new URL(process.env.DATABASE_URL);
    storageConfig = {
      type: 'postgres' as const,
      config: {
        host: dbUrl.hostname,
        port: parseInt(dbUrl.port || '5432', 10),
        database: dbUrl.pathname.slice(1),
        username: dbUrl.username,
        password: dbUrl.password,
      },
    };
  }

  return {
    agentType,
    agentName,
    agentPort,
    agentEndpoint,
    walletConfig: {
      id: `${agentName.toLowerCase()}-wallet`,
      key: process.env.WALLET_KEY || `${agentName}-wallet-key-secure-change-in-production`,
      keyDerivationMethod: KeyDerivationMethod.Argon2IMod,
      storage: storageConfig,
    },
    sectorType,
    fabricBridgeUrl,
  };
}

export function getInitConfig(config: AgentConfig): InitConfig {
  return {
    label: config.agentName,
    walletConfig: {
      id: config.walletConfig.id,
      key: config.walletConfig.key,
      keyDerivationMethod: config.walletConfig.keyDerivationMethod,
    },
    logger: {
      logLevel: LogLevel.info,
    },
  };
}

// Credential types definitions
export const CredentialTypes = {
  // Finance credentials
  KYCCredential: {
    type: 'KYCCredential',
    context: ['https://www.w3.org/2018/credentials/v1', 'https://crossdomain.com/credentials/finance/v1'],
    schema: {
      fullName: { type: 'string', required: true },
      dateOfBirth: { type: 'string', format: 'date', required: true },
      nationalID: { type: 'string', required: true },
      address: { type: 'object', required: true },
      verificationLevel: { type: 'string', enum: ['BASIC', 'STANDARD', 'ENHANCED'], required: true },
      verificationDate: { type: 'string', format: 'date-time', required: true },
      riskScore: { type: 'number', required: false },
    },
  },
  CreditScoreCredential: {
    type: 'CreditScoreCredential',
    context: ['https://www.w3.org/2018/credentials/v1', 'https://crossdomain.com/credentials/finance/v1'],
    schema: {
      creditScore: { type: 'number', required: true },
      scoreDate: { type: 'string', format: 'date', required: true },
      creditAgency: { type: 'string', required: true },
      riskCategory: { type: 'string', enum: ['LOW', 'MEDIUM', 'HIGH'], required: true },
    },
  },
  IncomeVerificationCredential: {
    type: 'IncomeVerificationCredential',
    context: ['https://www.w3.org/2018/credentials/v1', 'https://crossdomain.com/credentials/finance/v1'],
    schema: {
      annualIncome: { type: 'number', required: true },
      currency: { type: 'string', required: true },
      employmentStatus: { type: 'string', required: true },
      employer: { type: 'string', required: false },
      verificationDate: { type: 'string', format: 'date', required: true },
    },
  },

  // Healthcare credentials
  HealthInsuranceCredential: {
    type: 'HealthInsuranceCredential',
    context: ['https://www.w3.org/2018/credentials/v1', 'https://crossdomain.com/credentials/healthcare/v1'],
    schema: {
      policyNumber: { type: 'string', required: true },
      holderName: { type: 'string', required: true },
      coverageType: { type: 'string', enum: ['BASIC', 'STANDARD', 'PREMIUM', 'COMPREHENSIVE'], required: true },
      validFrom: { type: 'string', format: 'date', required: true },
      validUntil: { type: 'string', format: 'date', required: true },
      provider: { type: 'string', required: true },
      dependents: { type: 'array', required: false },
    },
  },
  VaccinationCredential: {
    type: 'VaccinationCredential',
    context: ['https://www.w3.org/2018/credentials/v1', 'https://crossdomain.com/credentials/healthcare/v1'],
    schema: {
      vaccinationType: { type: 'string', required: true },
      vaccinationDate: { type: 'string', format: 'date', required: true },
      batchNumber: { type: 'string', required: true },
      provider: { type: 'string', required: true },
      nextDoseDate: { type: 'string', format: 'date', required: false },
    },
  },
  MedicalClearanceCredential: {
    type: 'MedicalClearanceCredential',
    context: ['https://www.w3.org/2018/credentials/v1', 'https://crossdomain.com/credentials/healthcare/v1'],
    schema: {
      clearanceType: { type: 'string', required: true },
      issueDate: { type: 'string', format: 'date', required: true },
      validUntil: { type: 'string', format: 'date', required: true },
      restrictions: { type: 'array', required: false },
      issuingPhysician: { type: 'string', required: true },
    },
  },

  // Education credentials
  DiplomaCredential: {
    type: 'DiplomaCredential',
    context: ['https://www.w3.org/2018/credentials/v1', 'https://crossdomain.com/credentials/education/v1'],
    schema: {
      studentName: { type: 'string', required: true },
      studentID: { type: 'string', required: true },
      degree: { type: 'string', required: true },
      major: { type: 'string', required: true },
      graduationDate: { type: 'string', format: 'date', required: true },
      gpa: { type: 'number', required: false },
      honors: { type: 'string', enum: ['NONE', 'CUM_LAUDE', 'MAGNA_CUM_LAUDE', 'SUMMA_CUM_LAUDE'], required: false },
      institution: { type: 'string', required: true },
    },
  },
  TranscriptCredential: {
    type: 'TranscriptCredential',
    context: ['https://www.w3.org/2018/credentials/v1', 'https://crossdomain.com/credentials/education/v1'],
    schema: {
      studentName: { type: 'string', required: true },
      studentID: { type: 'string', required: true },
      courses: { type: 'array', required: true },
      totalCredits: { type: 'number', required: true },
      cumulativeGPA: { type: 'number', required: true },
      institution: { type: 'string', required: true },
      issueDate: { type: 'string', format: 'date', required: true },
    },
  },
  CertificateCredential: {
    type: 'CertificateCredential',
    context: ['https://www.w3.org/2018/credentials/v1', 'https://crossdomain.com/credentials/education/v1'],
    schema: {
      holderName: { type: 'string', required: true },
      certificateName: { type: 'string', required: true },
      issueDate: { type: 'string', format: 'date', required: true },
      expirationDate: { type: 'string', format: 'date', required: false },
      institution: { type: 'string', required: true },
      skills: { type: 'array', required: false },
    },
  },

  // Cross-domain credential
  FederatedIdentityCredential: {
    type: 'FederatedIdentityCredential',
    context: ['https://www.w3.org/2018/credentials/v1', 'https://crossdomain.com/credentials/federation/v1'],
    schema: {
      subjectDID: { type: 'string', required: true },
      sourceCredentials: { type: 'array', required: true },
      federationLevel: { type: 'string', enum: ['BASIC', 'VERIFIED', 'ASSURED'], required: true },
      sourceDomains: { type: 'array', required: true },
      validFrom: { type: 'string', format: 'date-time', required: true },
      validUntil: { type: 'string', format: 'date-time', required: true },
      trustChain: { type: 'array', required: false },
    },
  },
};

// Cross-domain mapping - which credentials can be used where
export const CrossDomainMapping = {
  FINANCE: {
    acceptsFrom: {
      EDUCATION: ['DiplomaCredential', 'TranscriptCredential', 'CertificateCredential'],
      HEALTHCARE: ['HealthInsuranceCredential'],
    },
    providesTo: {
      HEALTHCARE: ['KYCCredential', 'IncomeVerificationCredential'],
      EDUCATION: ['KYCCredential'],
    },
  },
  HEALTHCARE: {
    acceptsFrom: {
      FINANCE: ['KYCCredential', 'IncomeVerificationCredential'],
      EDUCATION: ['DiplomaCredential', 'CertificateCredential'],
    },
    providesTo: {
      FINANCE: ['HealthInsuranceCredential'],
      EDUCATION: ['VaccinationCredential', 'MedicalClearanceCredential'],
    },
  },
  EDUCATION: {
    acceptsFrom: {
      FINANCE: ['KYCCredential'],
      HEALTHCARE: ['VaccinationCredential', 'MedicalClearanceCredential'],
    },
    providesTo: {
      FINANCE: ['DiplomaCredential', 'TranscriptCredential', 'CertificateCredential'],
      HEALTHCARE: ['DiplomaCredential', 'CertificateCredential'],
    },
  },
};
