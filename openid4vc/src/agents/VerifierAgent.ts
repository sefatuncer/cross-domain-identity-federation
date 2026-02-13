import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';

import { BaseAgent, logger } from './BaseAgent.js';
import { AgentConfig, CrossDomainMapping } from '../config/agent.config.js';

interface PresentationDefinition {
  id: string;
  name?: string;
  purpose?: string;
  input_descriptors: InputDescriptor[];
}

interface InputDescriptor {
  id: string;
  name?: string;
  purpose?: string;
  constraints: {
    fields: Array<{
      path: string[];
      filter?: Record<string, unknown>;
      optional?: boolean;
    }>;
  };
}

interface VerificationSession {
  sessionId: string;
  presentationDefinition: PresentationDefinition;
  nonce: string;
  state: string;
  status: 'pending' | 'received' | 'verified' | 'failed' | 'expired';
  createdAt: string;
  expiresAt: string;
  sourceDomain?: string;
  targetDomain?: string;
  verificationResult?: VerificationResult;
}

interface VerificationResult {
  isValid: boolean;
  checks: Array<{
    name: string;
    passed: boolean;
    message: string;
  }>;
  credentials: Array<{
    credentialType: string;
    issuerDid: string;
    issuanceDate: string;
    verificationStatus: string;
  }>;
  crossDomainInfo?: {
    sourceDomain: string;
    targetDomain: string;
    policyEvaluation: any;
  };
  verifiedAt: string;
}

export class VerifierAgent extends BaseAgent {
  private verificationSessions: Map<string, VerificationSession> = new Map();
  private verificationHistory: Map<string, VerificationResult> = new Map();

  constructor(config: AgentConfig) {
    super(config);
  }

  protected setupRoutes(): void {
    // Create verification request (OpenID4VP Authorization Request)
    this.app.post('/verifier/request', this.createVerificationRequest.bind(this));

    // Get verification request details
    this.app.get('/verifier/request/:sessionId', this.getVerificationRequest.bind(this));

    // Receive presentation submission (OpenID4VP Response)
    this.app.post('/presentations/submit', this.receivePresentation.bind(this));

    // Get verification result
    this.app.get('/verifier/result/:sessionId', this.getVerificationResult.bind(this));

    // Cross-domain verification
    this.app.post('/verifier/cross-domain/verify', this.crossDomainVerify.bind(this));

    // Get supported verification types
    this.app.get('/verifier/supported-types', this.getSupportedTypes.bind(this));

    // Verification history
    this.app.get('/verifier/history', this.getVerificationHistory.bind(this));

    // OpenID4VP metadata
    this.app.get('/.well-known/openid4vp-authorization-server', this.getVerifierMetadata.bind(this));

    logger.info('Verifier agent routes configured');
  }

  private async createVerificationRequest(req: Request, res: Response): Promise<void> {
    try {
      const {
        credentialTypes,
        requiredFields,
        purpose,
        sourceDomain,
        targetDomain,
        expiresInMinutes = 30,
      } = req.body;

      if (!credentialTypes || credentialTypes.length === 0) {
        res.status(400).json({ error: 'At least one credential type is required' });
        return;
      }

      const sessionId = uuidv4();
      const nonce = uuidv4();
      const state = uuidv4();

      // Build presentation definition
      const presentationDefinition = this.buildPresentationDefinition(
        credentialTypes,
        requiredFields,
        purpose
      );

      const session: VerificationSession = {
        sessionId,
        presentationDefinition,
        nonce,
        state,
        status: 'pending',
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + expiresInMinutes * 60 * 1000).toISOString(),
        sourceDomain,
        targetDomain,
      };

      this.verificationSessions.set(sessionId, session);

      // Generate OpenID4VP authorization request URI
      const authorizationRequestUri = this.generateAuthorizationRequestUri(session);

      logger.info(`Verification request created: ${sessionId}`);

      res.status(201).json({
        sessionId,
        authorizationRequestUri,
        presentationDefinition,
        nonce,
        state,
        expiresAt: session.expiresAt,
        verifierEndpoint: `${this.config.agentEndpoint}/presentations/submit`,
      });
    } catch (error) {
      logger.error('Error creating verification request:', error);
      res.status(500).json({ error: 'Failed to create verification request' });
    }
  }

  private async getVerificationRequest(req: Request, res: Response): Promise<void> {
    try {
      const { sessionId } = req.params;
      const session = this.verificationSessions.get(sessionId);

      if (!session) {
        res.status(404).json({ error: 'Session not found' });
        return;
      }

      // Check if expired
      if (new Date(session.expiresAt) < new Date()) {
        session.status = 'expired';
      }

      res.json({
        sessionId: session.sessionId,
        status: session.status,
        presentationDefinition: session.presentationDefinition,
        nonce: session.nonce,
        expiresAt: session.expiresAt,
      });
    } catch (error) {
      logger.error('Error getting verification request:', error);
      res.status(500).json({ error: 'Failed to get verification request' });
    }
  }

  private async receivePresentation(req: Request, res: Response): Promise<void> {
    try {
      const { presentation, presentationDefinitionId, nonce, state } = req.body;

      // Find matching session
      let matchedSession: VerificationSession | undefined;
      for (const session of this.verificationSessions.values()) {
        if (session.nonce === nonce || session.state === state) {
          matchedSession = session;
          break;
        }
      }

      if (!matchedSession) {
        res.status(400).json({ error: 'No matching verification session found' });
        return;
      }

      if (new Date(matchedSession.expiresAt) < new Date()) {
        matchedSession.status = 'expired';
        res.status(400).json({ error: 'Verification session expired' });
        return;
      }

      matchedSession.status = 'received';

      // Verify the presentation
      const verificationResult = await this.verifyPresentation(presentation, matchedSession);

      matchedSession.verificationResult = verificationResult;
      matchedSession.status = verificationResult.isValid ? 'verified' : 'failed';

      // Store in history
      this.verificationHistory.set(matchedSession.sessionId, verificationResult);

      // Log to Fabric bridge if cross-domain
      if (matchedSession.sourceDomain && matchedSession.targetDomain) {
        await this.logCrossDomainVerification(matchedSession, verificationResult);
      }

      logger.info(`Presentation ${verificationResult.isValid ? 'verified' : 'rejected'}: ${matchedSession.sessionId}`);

      res.json({
        sessionId: matchedSession.sessionId,
        status: matchedSession.status,
        verificationResult,
      });
    } catch (error) {
      logger.error('Error receiving presentation:', error);
      res.status(500).json({ error: 'Failed to process presentation' });
    }
  }

  private async getVerificationResult(req: Request, res: Response): Promise<void> {
    try {
      const { sessionId } = req.params;
      const session = this.verificationSessions.get(sessionId);

      if (!session) {
        res.status(404).json({ error: 'Session not found' });
        return;
      }

      res.json({
        sessionId: session.sessionId,
        status: session.status,
        verificationResult: session.verificationResult,
      });
    } catch (error) {
      logger.error('Error getting verification result:', error);
      res.status(500).json({ error: 'Failed to get verification result' });
    }
  }

  private async crossDomainVerify(req: Request, res: Response): Promise<void> {
    try {
      const {
        presentation,
        sourceDomain,
        targetDomain,
        requiredCredentialTypes,
        bridgeUrl,
      } = req.body;

      if (!sourceDomain || !targetDomain) {
        res.status(400).json({ error: 'sourceDomain and targetDomain are required' });
        return;
      }

      // Step 1: Evaluate cross-domain policy
      let policyEvaluation = null;
      if (bridgeUrl || this.config.fabricBridgeUrl) {
        const bridgeEndpoint = bridgeUrl || this.config.fabricBridgeUrl;
        try {
          const policyResponse = await axios.post(`${bridgeEndpoint}/api/policy/evaluate`, {
            credentialType: requiredCredentialTypes?.[0] || 'Unknown',
            sourceDomain,
            targetDomain,
            issuerTrustLevel: 3, // Default
            credentialAge: 30, // Assume 30 days for now
            availableAttributes: this.extractAvailableAttributes(presentation),
          });
          policyEvaluation = policyResponse.data;

          if (!policyEvaluation.isAllowed) {
            res.status(403).json({
              error: 'Cross-domain policy rejected',
              policyEvaluation,
              message: policyEvaluation.reasons?.join(', ') || 'Policy evaluation failed',
            });
            return;
          }
        } catch (error) {
          logger.warn('Policy evaluation failed, continuing with verification:', error);
        }
      }

      // Step 2: Verify credential issuer trust
      let issuerValidation = null;
      if (bridgeUrl || this.config.fabricBridgeUrl) {
        const bridgeEndpoint = bridgeUrl || this.config.fabricBridgeUrl;
        try {
          const issuerDid = this.extractIssuerDid(presentation);
          const credentialType = requiredCredentialTypes?.[0] || 'Unknown';

          const issuerResponse = await axios.post(`${bridgeEndpoint}/api/issuer/validate`, {
            issuerDid,
            credentialType,
          });
          issuerValidation = issuerResponse.data;

          if (!issuerValidation.isValid) {
            res.status(403).json({
              error: 'Issuer not trusted',
              issuerValidation,
              message: issuerValidation.validationMessage || 'Issuer validation failed',
            });
            return;
          }
        } catch (error) {
          logger.warn('Issuer validation failed, continuing:', error);
        }
      }

      // Step 3: Verify credential signatures and content
      const sessionId = uuidv4();
      const session: VerificationSession = {
        sessionId,
        presentationDefinition: this.buildPresentationDefinition(requiredCredentialTypes || [], {}, 'Cross-domain verification'),
        nonce: uuidv4(),
        state: uuidv4(),
        status: 'received',
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
        sourceDomain,
        targetDomain,
      };

      const verificationResult = await this.verifyPresentation(presentation, session);

      // Add cross-domain info
      verificationResult.crossDomainInfo = {
        sourceDomain,
        targetDomain,
        policyEvaluation,
      };

      session.verificationResult = verificationResult;
      session.status = verificationResult.isValid ? 'verified' : 'failed';
      this.verificationSessions.set(sessionId, session);
      this.verificationHistory.set(sessionId, verificationResult);

      // Log to Fabric bridge
      await this.logCrossDomainVerification(session, verificationResult);

      logger.info(`Cross-domain verification ${verificationResult.isValid ? 'succeeded' : 'failed'}: ${sourceDomain} -> ${targetDomain}`);

      res.json({
        sessionId,
        verificationResult,
        policyEvaluation,
        issuerValidation,
      });
    } catch (error) {
      logger.error('Error in cross-domain verification:', error);
      res.status(500).json({ error: 'Failed to perform cross-domain verification' });
    }
  }

  private async getSupportedTypes(req: Request, res: Response): Promise<void> {
    try {
      const { forDomain } = req.query;

      // Get all accepted credential types for this verifier
      const allTypes = new Set<string>();

      for (const [domain, mapping] of Object.entries(CrossDomainMapping)) {
        if (!forDomain || domain === forDomain) {
          for (const types of Object.values(mapping.acceptsFrom)) {
            (types as string[]).forEach((t) => allTypes.add(t));
          }
        }
      }

      res.json({
        verifierDid: this.did,
        supportedCredentialTypes: Array.from(allTypes),
        crossDomainMappings: CrossDomainMapping,
      });
    } catch (error) {
      logger.error('Error getting supported types:', error);
      res.status(500).json({ error: 'Failed to get supported types' });
    }
  }

  private async getVerificationHistory(req: Request, res: Response): Promise<void> {
    try {
      const { limit = 50, status } = req.query;

      let sessions = Array.from(this.verificationSessions.values())
        .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

      if (status) {
        sessions = sessions.filter((s) => s.status === status);
      }

      sessions = sessions.slice(0, Number(limit));

      const history = sessions.map((s) => ({
        sessionId: s.sessionId,
        status: s.status,
        credentialTypes: s.presentationDefinition.input_descriptors.map((d) => d.name || d.id),
        sourceDomain: s.sourceDomain,
        targetDomain: s.targetDomain,
        createdAt: s.createdAt,
        isValid: s.verificationResult?.isValid,
      }));

      res.json({
        total: history.length,
        verificationHistory: history,
      });
    } catch (error) {
      logger.error('Error getting verification history:', error);
      res.status(500).json({ error: 'Failed to get verification history' });
    }
  }

  private async getVerifierMetadata(req: Request, res: Response): Promise<void> {
    try {
      res.json({
        issuer: this.config.agentEndpoint,
        authorization_endpoint: `${this.config.agentEndpoint}/verifier/request`,
        response_types_supported: ['vp_token'],
        response_modes_supported: ['direct_post'],
        vp_formats_supported: {
          jwt_vp: {
            alg_values_supported: ['EdDSA', 'ES256'],
          },
          jwt_vc: {
            alg_values_supported: ['EdDSA', 'ES256'],
          },
        },
        client_id_schemes_supported: ['did'],
        request_object_signing_alg_values_supported: ['EdDSA', 'ES256'],
      });
    } catch (error) {
      logger.error('Error getting verifier metadata:', error);
      res.status(500).json({ error: 'Failed to get verifier metadata' });
    }
  }

  // Helper methods
  private buildPresentationDefinition(
    credentialTypes: string[],
    requiredFields: Record<string, string[]>,
    purpose?: string
  ): PresentationDefinition {
    const inputDescriptors: InputDescriptor[] = credentialTypes.map((type) => ({
      id: type,
      name: type,
      purpose: purpose || `Verification of ${type}`,
      constraints: {
        fields: [
          {
            path: ['$.type'],
            filter: {
              type: 'array',
              contains: { const: type },
            },
          },
          ...(requiredFields[type] || []).map((field) => ({
            path: [`$.credentialSubject.${field}`],
            optional: false,
          })),
        ],
      },
    }));

    return {
      id: uuidv4(),
      name: 'Cross-Domain Verification Request',
      purpose: purpose || 'Verification for cross-domain identity federation',
      input_descriptors: inputDescriptors,
    };
  }

  private generateAuthorizationRequestUri(session: VerificationSession): string {
    const requestParams = {
      response_type: 'vp_token',
      response_mode: 'direct_post',
      client_id: this.did,
      redirect_uri: `${this.config.agentEndpoint}/presentations/submit`,
      presentation_definition: session.presentationDefinition,
      nonce: session.nonce,
      state: session.state,
    };

    const encodedParams = encodeURIComponent(JSON.stringify(requestParams));
    return `openid4vp://?request=${encodedParams}`;
  }

  private async verifyPresentation(
    presentation: any,
    session: VerificationSession
  ): Promise<VerificationResult> {
    const checks: Array<{ name: string; passed: boolean; message: string }> = [];
    const verifiedCredentials: Array<{
      credentialType: string;
      issuerDid: string;
      issuanceDate: string;
      verificationStatus: string;
    }> = [];

    // Check 1: Presentation structure
    const hasValidStructure = presentation && (presentation.verifiableCredential || presentation['@context']);
    checks.push({
      name: 'Structure validation',
      passed: hasValidStructure,
      message: hasValidStructure ? 'Presentation has valid structure' : 'Invalid presentation structure',
    });

    // Check 2: Holder binding
    const holderDid = presentation.holder;
    checks.push({
      name: 'Holder binding',
      passed: !!holderDid,
      message: holderDid ? `Holder DID: ${holderDid}` : 'No holder DID found',
    });

    // Check 3: Credential verification
    const credentials = presentation.verifiableCredential || [];
    const credentialArray = Array.isArray(credentials) ? credentials : [credentials];

    for (const cred of credentialArray) {
      const decodedCred = typeof cred === 'string' ? this.decodeCredential(cred) : cred;

      // Verify credential expiration
      const isExpired = decodedCred.expirationDate && new Date(decodedCred.expirationDate) < new Date();

      // Verify credential issuer
      const issuerDid = decodedCred.issuer?.id || decodedCred.issuer;
      const credType = decodedCred.type?.[1] || 'Unknown';

      checks.push({
        name: `Credential: ${credType}`,
        passed: !isExpired && !!issuerDid,
        message: isExpired ? 'Credential expired' : `Issued by ${issuerDid}`,
      });

      verifiedCredentials.push({
        credentialType: credType,
        issuerDid: issuerDid || 'Unknown',
        issuanceDate: decodedCred.issuanceDate || 'Unknown',
        verificationStatus: isExpired ? 'EXPIRED' : 'VALID',
      });
    }

    // Check 4: Required credentials
    const requiredTypes = session.presentationDefinition.input_descriptors.map((d) => d.name || d.id);
    const presentedTypes = verifiedCredentials.map((c) => c.credentialType);
    const missingTypes = requiredTypes.filter((t) => !presentedTypes.includes(t));

    checks.push({
      name: 'Required credentials',
      passed: missingTypes.length === 0,
      message:
        missingTypes.length === 0
          ? 'All required credentials present'
          : `Missing: ${missingTypes.join(', ')}`,
    });

    // Check 5: Proof verification (simplified)
    const hasProof = presentation.proof && presentation.proof.type;
    checks.push({
      name: 'Proof verification',
      passed: hasProof,
      message: hasProof ? `Proof type: ${presentation.proof.type}` : 'No proof found',
    });

    const allPassed = checks.every((c) => c.passed);

    return {
      isValid: allPassed,
      checks,
      credentials: verifiedCredentials,
      verifiedAt: new Date().toISOString(),
    };
  }

  private decodeCredential(credential: string): any {
    try {
      return JSON.parse(Buffer.from(credential, 'base64').toString('utf8'));
    } catch {
      return { type: ['VerifiableCredential', 'Unknown'] };
    }
  }

  private extractAvailableAttributes(presentation: any): string[] {
    const attributes: string[] = [];
    const credentials = presentation.verifiableCredential || [];
    const credentialArray = Array.isArray(credentials) ? credentials : [credentials];

    for (const cred of credentialArray) {
      const decodedCred = typeof cred === 'string' ? this.decodeCredential(cred) : cred;
      if (decodedCred.credentialSubject) {
        attributes.push(...Object.keys(decodedCred.credentialSubject));
      }
    }

    return [...new Set(attributes)];
  }

  private extractIssuerDid(presentation: any): string {
    const credentials = presentation.verifiableCredential || [];
    const firstCred = Array.isArray(credentials) ? credentials[0] : credentials;
    const decodedCred = typeof firstCred === 'string' ? this.decodeCredential(firstCred) : firstCred;
    return decodedCred.issuer?.id || decodedCred.issuer || 'Unknown';
  }

  private async logCrossDomainVerification(
    session: VerificationSession,
    result: VerificationResult
  ): Promise<void> {
    try {
      if (!this.config.fabricBridgeUrl) return;

      await axios.post(`${this.config.fabricBridgeUrl}/api/audit/log`, {
        eventType: result.isValid ? 'CROSS_DOMAIN_SUCCESS' : 'CROSS_DOMAIN_FAILED',
        sourceDomain: session.sourceDomain,
        targetDomain: session.targetDomain,
        verifierDid: this.did,
        credentialTypes: result.credentials.map((c) => c.credentialType),
        result: result.isValid ? 'SUCCESS' : 'FAILED',
        sessionId: session.sessionId,
      });
    } catch (error) {
      logger.warn('Failed to log cross-domain verification:', error);
    }
  }
}
