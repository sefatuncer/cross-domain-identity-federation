import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';

import { BaseAgent, logger } from './BaseAgent.js';
import { AgentConfig, CredentialTypes } from '../config/agent.config.js';

interface StoredCredential {
  id: string;
  credentialType: string;
  credential: string;
  issuerDid: string;
  issuedAt: string;
  expiresAt?: string;
  metadata: Record<string, unknown>;
}

interface PresentationRequest {
  verifierEndpoint: string;
  presentationDefinition: {
    id: string;
    input_descriptors: Array<{
      id: string;
      name?: string;
      purpose?: string;
      constraints: {
        fields: Array<{
          path: string[];
          filter?: Record<string, unknown>;
        }>;
      };
    }>;
  };
  nonce: string;
  state?: string;
}

export class HolderAgent extends BaseAgent {
  private credentials: Map<string, StoredCredential> = new Map();
  private pendingPresentations: Map<string, PresentationRequest> = new Map();

  constructor(config: AgentConfig) {
    super(config);
  }

  protected setupRoutes(): void {
    // Credential management
    this.app.post('/wallet/credentials/accept', this.acceptCredentialOffer.bind(this));
    this.app.get('/wallet/credentials', this.listCredentials.bind(this));
    this.app.get('/wallet/credentials/:id', this.getCredential.bind(this));
    this.app.delete('/wallet/credentials/:id', this.deleteCredential.bind(this));

    // Presentation
    this.app.post('/wallet/presentations/receive', this.receivePresentationRequest.bind(this));
    this.app.post('/wallet/presentations/submit', this.submitPresentation.bind(this));
    this.app.get('/wallet/presentations/pending', this.getPendingPresentations.bind(this));

    // Cross-domain
    this.app.post('/wallet/cross-domain/request', this.requestCrossDomainAccess.bind(this));
    this.app.get('/wallet/cross-domain/compatible', this.getCompatibleCredentials.bind(this));

    logger.info('Holder agent routes configured');
  }

  private async acceptCredentialOffer(req: Request, res: Response): Promise<void> {
    try {
      const { credentialOfferUri, issuerEndpoint } = req.body;

      let credentialOffer: any;

      if (credentialOfferUri) {
        // Parse credential offer URI
        const url = new URL(credentialOfferUri.replace('openid-credential-offer://', 'https://example.com'));
        const offerParam = url.searchParams.get('credential_offer');
        if (offerParam) {
          credentialOffer = JSON.parse(decodeURIComponent(offerParam));
        }
      }

      if (!credentialOffer && !issuerEndpoint) {
        res.status(400).json({ error: 'Either credentialOfferUri or issuerEndpoint is required' });
        return;
      }

      const issuer = credentialOffer?.credential_issuer || issuerEndpoint;
      const preAuthorizedCode = credentialOffer?.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code'];

      if (!preAuthorizedCode) {
        res.status(400).json({ error: 'Pre-authorized code not found in offer' });
        return;
      }

      // Step 1: Get access token
      const tokenResponse = await axios.post(`${issuer}/credentials/token`, {
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        pre_authorized_code: preAuthorizedCode,
      });

      const { access_token, c_nonce } = tokenResponse.data;

      // Step 2: Request credential
      const credentialResponse = await axios.post(
        `${issuer}/credentials/credential`,
        {
          format: 'jwt_vc_json',
          credential_definition: {
            type: credentialOffer?.credentials?.[0] || 'VerifiableCredential',
          },
          proof: {
            proof_type: 'jwt',
            jwt: this.createProofJwt(c_nonce),
          },
        },
        {
          headers: {
            Authorization: `Bearer ${access_token}`,
          },
        }
      );

      const { credential } = credentialResponse.data;

      // Parse and store credential
      const decodedCredential = this.decodeCredential(credential);
      const credentialId = uuidv4();

      const storedCredential: StoredCredential = {
        id: credentialId,
        credentialType: decodedCredential.type?.[1] || 'Unknown',
        credential,
        issuerDid: decodedCredential.issuer?.id || decodedCredential.issuer,
        issuedAt: decodedCredential.issuanceDate || new Date().toISOString(),
        expiresAt: decodedCredential.expirationDate,
        metadata: {
          rawCredential: decodedCredential,
        },
      };

      this.credentials.set(credentialId, storedCredential);

      logger.info(`Credential accepted and stored: ${credentialId}`);

      res.status(201).json({
        success: true,
        credentialId,
        credentialType: storedCredential.credentialType,
        issuer: storedCredential.issuerDid,
      });
    } catch (error: any) {
      logger.error('Error accepting credential offer:', error);
      res.status(500).json({
        error: 'Failed to accept credential offer',
        message: error.message,
      });
    }
  }

  private async listCredentials(req: Request, res: Response): Promise<void> {
    try {
      const { type, issuer } = req.query;

      let credentials = Array.from(this.credentials.values());

      if (type) {
        credentials = credentials.filter((c) => c.credentialType === type);
      }

      if (issuer) {
        credentials = credentials.filter((c) => c.issuerDid === issuer);
      }

      const summary = credentials.map((c) => ({
        id: c.id,
        credentialType: c.credentialType,
        issuerDid: c.issuerDid,
        issuedAt: c.issuedAt,
        expiresAt: c.expiresAt,
        isExpired: c.expiresAt ? new Date(c.expiresAt) < new Date() : false,
      }));

      res.json({
        holderDid: this.did,
        totalCredentials: credentials.length,
        credentials: summary,
      });
    } catch (error) {
      logger.error('Error listing credentials:', error);
      res.status(500).json({ error: 'Failed to list credentials' });
    }
  }

  private async getCredential(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const credential = this.credentials.get(id);

      if (!credential) {
        res.status(404).json({ error: 'Credential not found' });
        return;
      }

      res.json(credential);
    } catch (error) {
      logger.error('Error getting credential:', error);
      res.status(500).json({ error: 'Failed to get credential' });
    }
  }

  private async deleteCredential(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;

      if (!this.credentials.has(id)) {
        res.status(404).json({ error: 'Credential not found' });
        return;
      }

      this.credentials.delete(id);
      logger.info(`Credential deleted: ${id}`);

      res.json({ success: true, message: 'Credential deleted' });
    } catch (error) {
      logger.error('Error deleting credential:', error);
      res.status(500).json({ error: 'Failed to delete credential' });
    }
  }

  private async receivePresentationRequest(req: Request, res: Response): Promise<void> {
    try {
      const presentationRequest: PresentationRequest = req.body;

      if (!presentationRequest.presentationDefinition || !presentationRequest.verifierEndpoint) {
        res.status(400).json({ error: 'Invalid presentation request' });
        return;
      }

      const requestId = uuidv4();
      this.pendingPresentations.set(requestId, presentationRequest);

      // Find matching credentials
      const matchingCredentials = this.findMatchingCredentials(presentationRequest.presentationDefinition);

      logger.info(`Presentation request received: ${requestId}`);

      res.json({
        requestId,
        matchingCredentials: matchingCredentials.map((c) => ({
          id: c.id,
          credentialType: c.credentialType,
          issuerDid: c.issuerDid,
        })),
        canFulfill: matchingCredentials.length > 0,
        missingCredentialTypes: this.getMissingCredentialTypes(presentationRequest.presentationDefinition),
      });
    } catch (error) {
      logger.error('Error receiving presentation request:', error);
      res.status(500).json({ error: 'Failed to receive presentation request' });
    }
  }

  private async submitPresentation(req: Request, res: Response): Promise<void> {
    try {
      const { requestId, selectedCredentialIds, selectiveDisclosure } = req.body;

      const presentationRequest = this.pendingPresentations.get(requestId);
      if (!presentationRequest) {
        res.status(404).json({ error: 'Presentation request not found' });
        return;
      }

      // Get selected credentials
      const selectedCredentials = selectedCredentialIds
        .map((id: string) => this.credentials.get(id))
        .filter(Boolean) as StoredCredential[];

      if (selectedCredentials.length === 0) {
        res.status(400).json({ error: 'No valid credentials selected' });
        return;
      }

      // Build presentation
      const presentation = this.buildPresentation(
        selectedCredentials,
        presentationRequest,
        selectiveDisclosure
      );

      // Submit to verifier
      try {
        const verifierResponse = await axios.post(
          `${presentationRequest.verifierEndpoint}/presentations/submit`,
          {
            presentation,
            presentationDefinitionId: presentationRequest.presentationDefinition.id,
            nonce: presentationRequest.nonce,
            state: presentationRequest.state,
          }
        );

        this.pendingPresentations.delete(requestId);

        logger.info(`Presentation submitted for request: ${requestId}`);

        res.json({
          success: true,
          verifierResponse: verifierResponse.data,
        });
      } catch (verifierError: any) {
        logger.error('Verifier rejected presentation:', verifierError.response?.data);
        res.status(400).json({
          error: 'Presentation rejected by verifier',
          details: verifierError.response?.data,
        });
      }
    } catch (error) {
      logger.error('Error submitting presentation:', error);
      res.status(500).json({ error: 'Failed to submit presentation' });
    }
  }

  private async getPendingPresentations(req: Request, res: Response): Promise<void> {
    try {
      const pending = Array.from(this.pendingPresentations.entries()).map(([id, request]) => ({
        requestId: id,
        verifierEndpoint: request.verifierEndpoint,
        presentationDefinitionId: request.presentationDefinition.id,
        requestedCredentialTypes: request.presentationDefinition.input_descriptors.map((d) => d.name || d.id),
      }));

      res.json({ pendingPresentations: pending });
    } catch (error) {
      logger.error('Error getting pending presentations:', error);
      res.status(500).json({ error: 'Failed to get pending presentations' });
    }
  }

  private async requestCrossDomainAccess(req: Request, res: Response): Promise<void> {
    try {
      const { targetDomain, requiredCredentialTypes, verifierEndpoint, bridgeUrl } = req.body;

      // Find compatible credentials from wallet
      const compatibleCredentials = this.findCrossDomainCompatibleCredentials(
        targetDomain,
        requiredCredentialTypes
      );

      if (compatibleCredentials.length === 0) {
        res.status(400).json({
          error: 'No compatible credentials found',
          message: `No credentials in wallet that are accepted by ${targetDomain} domain`,
          requiredTypes: requiredCredentialTypes,
        });
        return;
      }

      // Check policy via bridge if available
      let policyEvaluation = null;
      if (bridgeUrl) {
        try {
          const policyResponse = await axios.post(`${bridgeUrl}/api/policy/evaluate`, {
            sourceDomains: [...new Set(compatibleCredentials.map((c) => this.getCredentialDomain(c)))],
            targetDomain,
            credentialTypes: compatibleCredentials.map((c) => c.credentialType),
          });
          policyEvaluation = policyResponse.data;
        } catch (error) {
          logger.warn('Could not evaluate policy:', error);
        }
      }

      res.json({
        targetDomain,
        compatibleCredentials: compatibleCredentials.map((c) => ({
          id: c.id,
          credentialType: c.credentialType,
          issuerDid: c.issuerDid,
          sourceDomain: this.getCredentialDomain(c),
        })),
        policyEvaluation,
        canProceed: policyEvaluation?.isAllowed !== false,
      });
    } catch (error) {
      logger.error('Error requesting cross-domain access:', error);
      res.status(500).json({ error: 'Failed to request cross-domain access' });
    }
  }

  private async getCompatibleCredentials(req: Request, res: Response): Promise<void> {
    try {
      const { targetDomain } = req.query;

      const allCredentials = Array.from(this.credentials.values());
      const compatible = targetDomain
        ? this.findCrossDomainCompatibleCredentials(targetDomain as string, [])
        : allCredentials;

      const grouped: Record<string, StoredCredential[]> = {};
      compatible.forEach((c) => {
        const domain = this.getCredentialDomain(c);
        if (!grouped[domain]) grouped[domain] = [];
        grouped[domain].push(c);
      });

      res.json({
        targetDomain: targetDomain || 'all',
        totalCompatible: compatible.length,
        bySourceDomain: Object.entries(grouped).map(([domain, creds]) => ({
          domain,
          credentials: creds.map((c) => ({
            id: c.id,
            credentialType: c.credentialType,
            issuerDid: c.issuerDid,
          })),
        })),
      });
    } catch (error) {
      logger.error('Error getting compatible credentials:', error);
      res.status(500).json({ error: 'Failed to get compatible credentials' });
    }
  }

  // Helper methods
  private decodeCredential(credential: string): any {
    try {
      // Assume base64 encoded JSON for now
      return JSON.parse(Buffer.from(credential, 'base64').toString('utf8'));
    } catch {
      return { type: ['VerifiableCredential', 'Unknown'] };
    }
  }

  private createProofJwt(nonce: string): string {
    // Simplified proof JWT - in production, this would be properly signed
    const header = { alg: 'EdDSA', typ: 'openid4vci-proof+jwt' };
    const payload = {
      iss: this.did,
      aud: 'issuer',
      iat: Math.floor(Date.now() / 1000),
      nonce,
    };
    return `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.signature`;
  }

  private findMatchingCredentials(presentationDefinition: any): StoredCredential[] {
    const matching: StoredCredential[] = [];

    for (const inputDescriptor of presentationDefinition.input_descriptors) {
      for (const credential of this.credentials.values()) {
        // Simple matching based on credential type
        const rawCredential = credential.metadata.rawCredential as any;
        if (rawCredential?.type?.includes(inputDescriptor.id) ||
            credential.credentialType === inputDescriptor.id ||
            inputDescriptor.name === credential.credentialType) {
          matching.push(credential);
        }
      }
    }

    return matching;
  }

  private getMissingCredentialTypes(presentationDefinition: any): string[] {
    const missing: string[] = [];

    for (const inputDescriptor of presentationDefinition.input_descriptors) {
      const found = Array.from(this.credentials.values()).some((c) => {
        const rawCredential = c.metadata.rawCredential as any;
        return (
          rawCredential?.type?.includes(inputDescriptor.id) ||
          c.credentialType === inputDescriptor.id ||
          inputDescriptor.name === c.credentialType
        );
      });

      if (!found) {
        missing.push(inputDescriptor.name || inputDescriptor.id);
      }
    }

    return missing;
  }

  private buildPresentation(
    credentials: StoredCredential[],
    request: PresentationRequest,
    selectiveDisclosure?: Record<string, string[]>
  ): any {
    return {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiablePresentation'],
      holder: this.did,
      verifiableCredential: credentials.map((c) => {
        if (selectiveDisclosure?.[c.id]) {
          // Apply selective disclosure
          return this.applySelectiveDisclosure(c, selectiveDisclosure[c.id]);
        }
        return c.credential;
      }),
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        challenge: request.nonce,
        proofPurpose: 'authentication',
        verificationMethod: this.did,
      },
    };
  }

  private applySelectiveDisclosure(credential: StoredCredential, disclosedFields: string[]): any {
    const rawCredential = credential.metadata.rawCredential as any;
    if (!rawCredential) return credential.credential;

    const disclosed = {
      ...rawCredential,
      credentialSubject: Object.fromEntries(
        Object.entries(rawCredential.credentialSubject || {}).filter(
          ([key]) => key === 'id' || disclosedFields.includes(key)
        )
      ),
    };

    return Buffer.from(JSON.stringify(disclosed)).toString('base64');
  }

  private findCrossDomainCompatibleCredentials(
    targetDomain: string,
    requiredTypes: string[]
  ): StoredCredential[] {
    // Define which credentials are accepted by each domain
    const acceptanceMapping: Record<string, string[]> = {
      FINANCE: ['DiplomaCredential', 'TranscriptCredential', 'CertificateCredential', 'HealthInsuranceCredential'],
      HEALTHCARE: ['KYCCredential', 'IncomeVerificationCredential', 'DiplomaCredential', 'CertificateCredential'],
      EDUCATION: ['KYCCredential', 'VaccinationCredential', 'MedicalClearanceCredential'],
    };

    const acceptedTypes = acceptanceMapping[targetDomain.toUpperCase()] || [];

    return Array.from(this.credentials.values()).filter((c) => {
      const isAccepted = acceptedTypes.includes(c.credentialType);
      const matchesRequired = requiredTypes.length === 0 || requiredTypes.includes(c.credentialType);
      return isAccepted && matchesRequired;
    });
  }

  private getCredentialDomain(credential: StoredCredential): string {
    const rawCredential = credential.metadata.rawCredential as any;
    const context = rawCredential?.['@context'] || [];

    if (context.some((c: string) => c.includes('/finance/'))) return 'FINANCE';
    if (context.some((c: string) => c.includes('/healthcare/'))) return 'HEALTHCARE';
    if (context.some((c: string) => c.includes('/education/'))) return 'EDUCATION';
    return 'UNKNOWN';
  }
}
