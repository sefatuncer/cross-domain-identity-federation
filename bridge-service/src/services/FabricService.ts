import * as grpc from '@grpc/grpc-js';
import {
  connect,
  Contract,
  Gateway,
  Identity,
  Signer,
  signers,
  Network,
} from '@hyperledger/fabric-gateway';
import * as crypto from 'crypto';
import { promises as fs } from 'fs';
import { BridgeConfig, CHAINCODES, CHANNELS } from '../config/config.js';
import { logger } from '../utils/logger.js';

export class FabricService {
  private config: BridgeConfig;
  private gateway?: Gateway;
  private client?: grpc.Client;
  private contracts: Map<string, Contract> = new Map();
  private useMockMode: boolean = true; // Default to mock mode for development

  constructor(config: BridgeConfig) {
    this.config = config;
  }

  async connect(): Promise<void> {
    try {
      // Check if we should use mock mode
      const certExists = await this.fileExists(this.config.fabric.certificatePath);
      const keyExists = await this.fileExists(this.config.fabric.privateKeyPath);

      if (!certExists || !keyExists) {
        logger.warn('Fabric credentials not found, running in mock mode');
        this.useMockMode = true;
        return;
      }

      this.useMockMode = false;

      // Load credentials
      const credentials = await this.loadCredentials();

      // Create gRPC client
      const tlsCredentials = grpc.credentials.createSsl(
        await fs.readFile(this.config.fabric.tlsCertPath)
      );

      this.client = new grpc.Client(
        this.config.fabric.peerEndpoint,
        tlsCredentials,
        {
          'grpc.ssl_target_name_override': this.config.fabric.gatewayHost,
        }
      );

      // Connect gateway
      this.gateway = connect({
        client: this.client,
        identity: credentials.identity,
        signer: credentials.signer,
        evaluateOptions: () => ({ deadline: Date.now() + 5000 }),
        endorseOptions: () => ({ deadline: Date.now() + 15000 }),
        submitOptions: () => ({ deadline: Date.now() + 5000 }),
        commitStatusOptions: () => ({ deadline: Date.now() + 60000 }),
      });

      logger.info('Connected to Hyperledger Fabric network');
    } catch (error) {
      logger.error('Failed to connect to Fabric network, running in mock mode:', error);
      this.useMockMode = true;
    }
  }

  private async fileExists(path: string): Promise<boolean> {
    try {
      await fs.access(path);
      return true;
    } catch {
      return false;
    }
  }

  private async loadCredentials(): Promise<{ identity: Identity; signer: Signer }> {
    const certificate = await fs.readFile(this.config.fabric.certificatePath, 'utf8');
    const privateKeyPem = await fs.readFile(this.config.fabric.privateKeyPath, 'utf8');

    const identity: Identity = {
      mspId: this.config.fabric.mspId,
      credentials: Buffer.from(certificate),
    };

    const privateKey = crypto.createPrivateKey(privateKeyPem);
    const signer = signers.newPrivateKeySigner(privateKey);

    return { identity, signer };
  }

  private getContract(channelName: string, chaincodeName: string): Contract | null {
    if (this.useMockMode || !this.gateway) {
      return null;
    }

    const key = `${channelName}:${chaincodeName}`;
    if (!this.contracts.has(key)) {
      const network = this.gateway.getNetwork(channelName);
      const contract = network.getContract(chaincodeName);
      this.contracts.set(key, contract);
    }
    return this.contracts.get(key)!;
  }

  // Trusted Issuer Registry Functions
  async validateIssuer(issuerDid: string, credentialType: string): Promise<any> {
    if (this.useMockMode) {
      return this.mockValidateIssuer(issuerDid, credentialType);
    }

    const contract = this.getContract(CHANNELS.GLOBAL, CHAINCODES.TRUSTED_ISSUER_REGISTRY);
    if (!contract) {
      return this.mockValidateIssuer(issuerDid, credentialType);
    }

    try {
      const result = await contract.evaluateTransaction('ValidateIssuer', issuerDid, credentialType);
      return JSON.parse(result.toString());
    } catch (error) {
      logger.error('Error validating issuer:', error);
      return this.mockValidateIssuer(issuerDid, credentialType);
    }
  }

  async queryIssuer(issuerDid: string): Promise<any> {
    if (this.useMockMode) {
      return this.mockQueryIssuer(issuerDid);
    }

    const contract = this.getContract(CHANNELS.GLOBAL, CHAINCODES.TRUSTED_ISSUER_REGISTRY);
    if (!contract) {
      return this.mockQueryIssuer(issuerDid);
    }

    try {
      const result = await contract.evaluateTransaction('QueryIssuer', issuerDid);
      return JSON.parse(result.toString());
    } catch (error) {
      logger.error('Error querying issuer:', error);
      return null;
    }
  }

  async registerIssuer(issuerData: any): Promise<void> {
    if (this.useMockMode) {
      logger.info('Mock: Registering issuer:', issuerData.issuerDID);
      return;
    }

    const contract = this.getContract(CHANNELS.GLOBAL, CHAINCODES.TRUSTED_ISSUER_REGISTRY);
    if (!contract) return;

    try {
      await contract.submitTransaction('RegisterIssuer', JSON.stringify(issuerData));
      logger.info(`Issuer registered: ${issuerData.issuerDID}`);
    } catch (error) {
      logger.error('Error registering issuer:', error);
      throw error;
    }
  }

  async getIssuersByType(orgType: string): Promise<any[]> {
    if (this.useMockMode) {
      return this.mockGetIssuersByType(orgType);
    }

    const contract = this.getContract(CHANNELS.GLOBAL, CHAINCODES.TRUSTED_ISSUER_REGISTRY);
    if (!contract) {
      return this.mockGetIssuersByType(orgType);
    }

    try {
      const result = await contract.evaluateTransaction('GetIssuersByType', orgType);
      return JSON.parse(result.toString());
    } catch (error) {
      logger.error('Error getting issuers by type:', error);
      return [];
    }
  }

  // Cross-Domain Policy Functions
  async evaluatePolicy(request: any): Promise<any> {
    if (this.useMockMode) {
      return this.mockEvaluatePolicy(request);
    }

    const contract = this.getContract(CHANNELS.CROSS_DOMAIN, CHAINCODES.CROSS_DOMAIN_POLICY);
    if (!contract) {
      return this.mockEvaluatePolicy(request);
    }

    try {
      const result = await contract.evaluateTransaction('EvaluatePolicy', JSON.stringify(request));
      return JSON.parse(result.toString());
    } catch (error) {
      logger.error('Error evaluating policy:', error);
      return this.mockEvaluatePolicy(request);
    }
  }

  async getAcceptedCredentialTypes(sourceDomain: string, targetDomain: string): Promise<string[]> {
    if (this.useMockMode) {
      return this.mockGetAcceptedTypes(sourceDomain, targetDomain);
    }

    const contract = this.getContract(CHANNELS.CROSS_DOMAIN, CHAINCODES.CROSS_DOMAIN_POLICY);
    if (!contract) {
      return this.mockGetAcceptedTypes(sourceDomain, targetDomain);
    }

    try {
      const result = await contract.evaluateTransaction('GetAcceptedCredentialTypes', sourceDomain, targetDomain);
      return JSON.parse(result.toString());
    } catch (error) {
      logger.error('Error getting accepted credential types:', error);
      return [];
    }
  }

  async logCrossDomainVerification(record: any): Promise<string> {
    if (this.useMockMode) {
      logger.info('Mock: Logging cross-domain verification:', record);
      return `mock-record-${Date.now()}`;
    }

    const contract = this.getContract(CHANNELS.CROSS_DOMAIN, CHAINCODES.CROSS_DOMAIN_POLICY);
    if (!contract) {
      return `mock-record-${Date.now()}`;
    }

    try {
      const result = await contract.submitTransaction('LogCrossDomainVerification', JSON.stringify(record));
      return result.toString();
    } catch (error) {
      logger.error('Error logging verification:', error);
      throw error;
    }
  }

  // Schema Registry Functions
  async getSchema(schemaId: string): Promise<any> {
    if (this.useMockMode) {
      return this.mockGetSchema(schemaId);
    }

    const contract = this.getContract(CHANNELS.GLOBAL, CHAINCODES.CREDENTIAL_SCHEMA_REGISTRY);
    if (!contract) {
      return this.mockGetSchema(schemaId);
    }

    try {
      const result = await contract.evaluateTransaction('GetSchema', schemaId);
      return JSON.parse(result.toString());
    } catch (error) {
      logger.error('Error getting schema:', error);
      return null;
    }
  }

  async validateCredentialSchema(credentialJson: string, schemaId: string): Promise<any> {
    if (this.useMockMode) {
      return { isValid: true, errors: [], matchedFields: [], missingFields: [] };
    }

    const contract = this.getContract(CHANNELS.GLOBAL, CHAINCODES.CREDENTIAL_SCHEMA_REGISTRY);
    if (!contract) {
      return { isValid: true, errors: [], matchedFields: [], missingFields: [] };
    }

    try {
      const result = await contract.evaluateTransaction('ValidateCredentialAgainstSchema', credentialJson, schemaId);
      return JSON.parse(result.toString());
    } catch (error) {
      logger.error('Error validating credential schema:', error);
      return { isValid: false, errors: ['Schema validation failed'] };
    }
  }

  // Privacy Audit Functions
  async logAuditEvent(eventData: any): Promise<string> {
    if (this.useMockMode) {
      logger.info('Mock: Logging audit event:', eventData.eventType);
      return `mock-event-${Date.now()}`;
    }

    const contract = this.getContract(CHANNELS.GLOBAL, CHAINCODES.PRIVACY_AUDIT);
    if (!contract) {
      return `mock-event-${Date.now()}`;
    }

    try {
      const result = await contract.submitTransaction('LogVerificationEvent', JSON.stringify(eventData));
      return result.toString();
    } catch (error) {
      logger.error('Error logging audit event:', error);
      throw error;
    }
  }

  async queryAuditLog(startTime: string, endTime: string, orgType?: string): Promise<any[]> {
    if (this.useMockMode) {
      return [];
    }

    const contract = this.getContract(CHANNELS.GLOBAL, CHAINCODES.PRIVACY_AUDIT);
    if (!contract) return [];

    try {
      const result = await contract.evaluateTransaction('QueryAuditLog', startTime, endTime, orgType || '');
      return JSON.parse(result.toString());
    } catch (error) {
      logger.error('Error querying audit log:', error);
      return [];
    }
  }

  async generateComplianceReport(orgId: string, period: string): Promise<any> {
    if (this.useMockMode) {
      return this.mockGenerateComplianceReport(orgId, period);
    }

    const contract = this.getContract(CHANNELS.GLOBAL, CHAINCODES.PRIVACY_AUDIT);
    if (!contract) {
      return this.mockGenerateComplianceReport(orgId, period);
    }

    try {
      const result = await contract.evaluateTransaction('GenerateComplianceReport', orgId, period);
      return JSON.parse(result.toString());
    } catch (error) {
      logger.error('Error generating compliance report:', error);
      return this.mockGenerateComplianceReport(orgId, period);
    }
  }

  async disconnect(): Promise<void> {
    if (this.gateway) {
      this.gateway.close();
    }
    if (this.client) {
      this.client.close();
    }
    logger.info('Disconnected from Fabric network');
  }

  // Mock implementations for development/testing
  private mockValidateIssuer(issuerDid: string, credentialType: string): any {
    const trustedIssuers = [
      'did:web:bank.finance.crossdomain.com',
      'did:web:hospital.healthcare.crossdomain.com',
      'did:web:university.education.crossdomain.com',
    ];

    const isTrusted = trustedIssuers.some((i) => issuerDid.includes(i.split('.')[0].split(':')[2]));

    return {
      isValid: isTrusted,
      issuerDID: issuerDid,
      organizationType: this.inferOrgType(issuerDid),
      trustLevel: isTrusted ? 5 : 0,
      allowedTypes: isTrusted ? [credentialType] : [],
      validationMessage: isTrusted ? 'Issuer is valid and trusted' : 'Issuer not found in trusted registry',
      timestamp: new Date().toISOString(),
    };
  }

  private mockQueryIssuer(issuerDid: string): any {
    return {
      issuerDID: issuerDid,
      organizationType: this.inferOrgType(issuerDid),
      organizationName: 'Mock Organization',
      status: 'ACTIVE',
      trustLevel: 5,
      credentialTypes: ['KYCCredential', 'DiplomaCredential'],
    };
  }

  private mockGetIssuersByType(orgType: string): any[] {
    return [
      {
        issuerDID: `did:web:mock.${orgType.toLowerCase()}.crossdomain.com`,
        organizationType: orgType,
        status: 'ACTIVE',
        trustLevel: 5,
      },
    ];
  }

  private mockEvaluatePolicy(request: any): any {
    // Simple mock policy evaluation
    const crossDomainAllowed: Record<string, Record<string, string[]>> = {
      FINANCE: {
        HEALTHCARE: ['KYCCredential', 'IncomeVerificationCredential'],
        EDUCATION: ['KYCCredential'],
      },
      HEALTHCARE: {
        FINANCE: ['HealthInsuranceCredential'],
        EDUCATION: ['VaccinationCredential', 'MedicalClearanceCredential'],
      },
      EDUCATION: {
        FINANCE: ['DiplomaCredential', 'TranscriptCredential', 'CertificateCredential'],
        HEALTHCARE: ['DiplomaCredential', 'CertificateCredential'],
      },
    };

    const sourceAllowed = crossDomainAllowed[request.sourceDomain];
    const targetAllowed = sourceAllowed?.[request.targetDomain] || [];
    const isAllowed = targetAllowed.includes(request.credentialType);

    return {
      isAllowed,
      policyID: 'mock-policy-1',
      matchedRuleID: isAllowed ? 'mock-rule-1' : null,
      reasons: isAllowed
        ? ['All policy requirements satisfied']
        : [`Credential type ${request.credentialType} not accepted from ${request.sourceDomain} to ${request.targetDomain}`],
      requiredAttributes: [],
      missingAttributes: [],
      allowSelectiveDisclosure: true,
      evaluatedAt: new Date().toISOString(),
    };
  }

  private mockGetAcceptedTypes(sourceDomain: string, targetDomain: string): string[] {
    const mapping: Record<string, Record<string, string[]>> = {
      FINANCE: {
        HEALTHCARE: ['KYCCredential', 'IncomeVerificationCredential'],
        EDUCATION: ['KYCCredential'],
      },
      HEALTHCARE: {
        FINANCE: ['HealthInsuranceCredential'],
        EDUCATION: ['VaccinationCredential', 'MedicalClearanceCredential'],
      },
      EDUCATION: {
        FINANCE: ['DiplomaCredential', 'TranscriptCredential', 'CertificateCredential'],
        HEALTHCARE: ['DiplomaCredential', 'CertificateCredential'],
      },
    };

    return mapping[sourceDomain]?.[targetDomain] || [];
  }

  private mockGetSchema(schemaId: string): any {
    return {
      schemaID: schemaId,
      schemaName: schemaId.split(':')[2] || 'Unknown',
      status: 'ACTIVE',
      properties: [],
    };
  }

  private mockGenerateComplianceReport(orgId: string, period: string): any {
    return {
      reportID: `mock-report-${Date.now()}`,
      organizationID: orgId,
      reportPeriod: period,
      generatedAt: new Date().toISOString(),
      totalEvents: 100,
      eventsByType: {
        CREDENTIAL_ISSUED: 50,
        CREDENTIAL_VERIFIED: 40,
        CROSS_DOMAIN_SUCCESS: 10,
      },
      crossDomainStats: {
        totalRequests: 15,
        successCount: 10,
        failedCount: 5,
        successRate: 66.67,
      },
      complianceStatus: 'COMPLIANT',
      findings: [],
      recommendations: [],
    };
  }

  private inferOrgType(did: string): string {
    if (did.includes('finance') || did.includes('bank')) return 'FINANCE';
    if (did.includes('health') || did.includes('hospital')) return 'HEALTHCARE';
    if (did.includes('education') || did.includes('university')) return 'EDUCATION';
    return 'UNKNOWN';
  }
}
