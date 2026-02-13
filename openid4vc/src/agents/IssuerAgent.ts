import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';

import { BaseAgent, logger } from './BaseAgent.js';
import { AgentConfig, CredentialTypes, CrossDomainMapping } from '../config/agent.config.js';

interface CredentialOfferRequest {
  credentialType: string;
  subjectDid: string;
  claims: Record<string, unknown>;
  validityPeriod?: number; // in days
}

interface CredentialOffer {
  offerId: string;
  credentialType: string;
  issuerDid: string;
  subjectDid: string;
  claims: Record<string, unknown>;
  status: 'pending' | 'accepted' | 'issued' | 'rejected' | 'expired';
  createdAt: string;
  expiresAt: string;
  credentialEndpoint: string;
  preAuthorizedCode?: string;
}

export class IssuerAgent extends BaseAgent {
  private credentialOffers: Map<string, CredentialOffer> = new Map();
  private issuedCredentials: Map<string, unknown> = new Map();

  constructor(config: AgentConfig) {
    super(config);
  }

  protected setupRoutes(): void {
    // Create credential offer
    this.app.post('/credentials/offer', this.createCredentialOffer.bind(this));

    // Get credential offer details
    this.app.get('/credentials/offer/:offerId', this.getCredentialOffer.bind(this));

    // Issue credential (token endpoint)
    this.app.post('/credentials/token', this.tokenEndpoint.bind(this));

    // Credential endpoint
    this.app.post('/credentials/credential', this.credentialEndpoint.bind(this));

    // List supported credential types
    this.app.get('/credentials/types', this.getSupportedCredentialTypes.bind(this));

    // Get issuer metadata (OpenID4VCI)
    this.app.get('/.well-known/openid-credential-issuer', this.getIssuerMetadata.bind(this));

    // Authorization server metadata
    this.app.get('/.well-known/oauth-authorization-server', this.getAuthServerMetadata.bind(this));

    // Revoke credential
    this.app.post('/credentials/revoke', this.revokeCredential.bind(this));

    // Get issued credentials (for audit)
    this.app.get('/credentials/issued', this.getIssuedCredentials.bind(this));

    logger.info(`Issuer agent routes configured for ${this.config.sectorType} sector`);
  }

  private async createCredentialOffer(req: Request, res: Response): Promise<void> {
    try {
      const { credentialType, subjectDid, claims, validityPeriod } = req.body as CredentialOfferRequest;

      // Validate credential type for this sector
      if (!this.isCredentialTypeSupported(credentialType)) {
        res.status(400).json({
          error: 'Unsupported credential type',
          message: `This issuer does not support ${credentialType}`,
          supportedTypes: this.getSupportedTypes(),
        });
        return;
      }

      // Validate claims against schema
      const validationResult = this.validateClaims(credentialType, claims);
      if (!validationResult.valid) {
        res.status(400).json({
          error: 'Invalid claims',
          message: validationResult.errors.join(', '),
        });
        return;
      }

      // Verify issuer is trusted (via Fabric bridge)
      const isTrusted = await this.verifyIssuerTrust(credentialType);
      if (!isTrusted) {
        res.status(403).json({
          error: 'Issuer not trusted',
          message: 'This issuer is not registered in the trusted issuer registry',
        });
        return;
      }

      const offerId = uuidv4();
      const preAuthorizedCode = uuidv4();
      const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24 hours

      const offer: CredentialOffer = {
        offerId,
        credentialType,
        issuerDid: this.did!,
        subjectDid,
        claims,
        status: 'pending',
        createdAt: new Date().toISOString(),
        expiresAt,
        credentialEndpoint: `${this.config.agentEndpoint}/credentials/credential`,
        preAuthorizedCode,
      };

      this.credentialOffers.set(offerId, offer);

      // Generate OpenID4VCI credential offer URI
      const credentialOfferUri = this.generateCredentialOfferUri(offer);

      logger.info(`Credential offer created: ${offerId} for type ${credentialType}`);

      res.status(201).json({
        offerId,
        credentialOfferUri,
        expiresAt,
        credentialEndpoint: offer.credentialEndpoint,
        preAuthorizedCode,
      });
    } catch (error) {
      logger.error('Error creating credential offer:', error);
      res.status(500).json({ error: 'Failed to create credential offer' });
    }
  }

  private async getCredentialOffer(req: Request, res: Response): Promise<void> {
    try {
      const { offerId } = req.params;
      const offer = this.credentialOffers.get(offerId);

      if (!offer) {
        res.status(404).json({ error: 'Offer not found' });
        return;
      }

      res.json(offer);
    } catch (error) {
      logger.error('Error getting credential offer:', error);
      res.status(500).json({ error: 'Failed to get credential offer' });
    }
  }

  private async tokenEndpoint(req: Request, res: Response): Promise<void> {
    try {
      const { grant_type, pre_authorized_code } = req.body;

      if (grant_type !== 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
        res.status(400).json({ error: 'unsupported_grant_type' });
        return;
      }

      // Find offer by pre-authorized code
      let matchedOffer: CredentialOffer | undefined;
      for (const offer of this.credentialOffers.values()) {
        if (offer.preAuthorizedCode === pre_authorized_code) {
          matchedOffer = offer;
          break;
        }
      }

      if (!matchedOffer) {
        res.status(400).json({ error: 'invalid_grant' });
        return;
      }

      if (new Date(matchedOffer.expiresAt) < new Date()) {
        matchedOffer.status = 'expired';
        res.status(400).json({ error: 'expired_grant' });
        return;
      }

      // Generate access token
      const accessToken = uuidv4();
      matchedOffer.status = 'accepted';

      res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        c_nonce: uuidv4(),
        c_nonce_expires_in: 86400,
      });
    } catch (error) {
      logger.error('Error in token endpoint:', error);
      res.status(500).json({ error: 'server_error' });
    }
  }

  private async credentialEndpoint(req: Request, res: Response): Promise<void> {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ error: 'invalid_token' });
        return;
      }

      const { format, credential_definition, proof } = req.body;

      // For simplicity, find the first accepted offer
      let matchedOffer: CredentialOffer | undefined;
      for (const offer of this.credentialOffers.values()) {
        if (offer.status === 'accepted') {
          matchedOffer = offer;
          break;
        }
      }

      if (!matchedOffer) {
        res.status(400).json({ error: 'invalid_request' });
        return;
      }

      // Issue the credential
      const credential = await this.issueCredential(matchedOffer);
      matchedOffer.status = 'issued';

      // Store issued credential
      const credentialId = uuidv4();
      this.issuedCredentials.set(credentialId, {
        id: credentialId,
        credential,
        offer: matchedOffer,
        issuedAt: new Date().toISOString(),
        revoked: false,
      });

      // Log to Fabric bridge
      await this.logCredentialIssuance(matchedOffer, credentialId);

      logger.info(`Credential issued: ${credentialId} for type ${matchedOffer.credentialType}`);

      res.json({
        format: 'jwt_vc_json',
        credential,
        c_nonce: uuidv4(),
        c_nonce_expires_in: 86400,
      });
    } catch (error) {
      logger.error('Error in credential endpoint:', error);
      res.status(500).json({ error: 'server_error' });
    }
  }

  private async getSupportedCredentialTypes(req: Request, res: Response): Promise<void> {
    try {
      const types = this.getSupportedTypes();
      const detailedTypes = types.map((type) => ({
        type,
        schema: CredentialTypes[type as keyof typeof CredentialTypes],
        crossDomainAccepted: this.getCrossDomainAcceptance(type),
      }));

      res.json({
        issuerDid: this.did,
        sectorType: this.config.sectorType,
        supportedCredentialTypes: detailedTypes,
      });
    } catch (error) {
      logger.error('Error getting supported credential types:', error);
      res.status(500).json({ error: 'Failed to get supported credential types' });
    }
  }

  private async getIssuerMetadata(req: Request, res: Response): Promise<void> {
    try {
      const supportedTypes = this.getSupportedTypes();
      const credentialsSupported: Record<string, unknown> = {};

      supportedTypes.forEach((type) => {
        const credentialDef = CredentialTypes[type as keyof typeof CredentialTypes];
        credentialsSupported[type] = {
          format: 'jwt_vc_json',
          scope: type.toLowerCase(),
          cryptographic_binding_methods_supported: ['did:key', 'did:web'],
          credential_signing_alg_values_supported: ['EdDSA', 'ES256'],
          credential_definition: {
            type: ['VerifiableCredential', type],
            credentialSubject: credentialDef?.schema || {},
          },
          display: [
            {
              name: type,
              locale: 'en-US',
            },
          ],
        };
      });

      res.json({
        credential_issuer: this.config.agentEndpoint,
        authorization_servers: [this.config.agentEndpoint],
        credential_endpoint: `${this.config.agentEndpoint}/credentials/credential`,
        token_endpoint: `${this.config.agentEndpoint}/credentials/token`,
        credentials_supported: credentialsSupported,
        display: [
          {
            name: `${this.config.sectorType?.toUpperCase()} Sector Issuer`,
            locale: 'en-US',
          },
        ],
      });
    } catch (error) {
      logger.error('Error getting issuer metadata:', error);
      res.status(500).json({ error: 'Failed to get issuer metadata' });
    }
  }

  private async getAuthServerMetadata(req: Request, res: Response): Promise<void> {
    try {
      res.json({
        issuer: this.config.agentEndpoint,
        token_endpoint: `${this.config.agentEndpoint}/credentials/token`,
        token_endpoint_auth_methods_supported: ['none'],
        grant_types_supported: ['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
        pre_authorized_grant_anonymous_access_supported: true,
      });
    } catch (error) {
      logger.error('Error getting auth server metadata:', error);
      res.status(500).json({ error: 'Failed to get auth server metadata' });
    }
  }

  private async revokeCredential(req: Request, res: Response): Promise<void> {
    try {
      const { credentialId, reason } = req.body;

      const issuedCred = this.issuedCredentials.get(credentialId);
      if (!issuedCred) {
        res.status(404).json({ error: 'Credential not found' });
        return;
      }

      // Mark as revoked
      (issuedCred as any).revoked = true;
      (issuedCred as any).revokedAt = new Date().toISOString();
      (issuedCred as any).revocationReason = reason;

      // Log revocation to Fabric bridge
      await this.logCredentialRevocation(credentialId, reason);

      logger.info(`Credential revoked: ${credentialId}`);

      res.json({ success: true, credentialId, revokedAt: (issuedCred as any).revokedAt });
    } catch (error) {
      logger.error('Error revoking credential:', error);
      res.status(500).json({ error: 'Failed to revoke credential' });
    }
  }

  private async getIssuedCredentials(req: Request, res: Response): Promise<void> {
    try {
      const credentials = Array.from(this.issuedCredentials.values()).map((cred: any) => ({
        id: cred.id,
        credentialType: cred.offer.credentialType,
        subjectDid: cred.offer.subjectDid,
        issuedAt: cred.issuedAt,
        revoked: cred.revoked,
        revokedAt: cred.revokedAt,
      }));

      res.json({
        issuerDid: this.did,
        totalIssued: credentials.length,
        credentials,
      });
    } catch (error) {
      logger.error('Error getting issued credentials:', error);
      res.status(500).json({ error: 'Failed to get issued credentials' });
    }
  }

  // Helper methods
  private getSupportedTypes(): string[] {
    const sectorType = this.config.sectorType?.toUpperCase();
    const types: string[] = [];

    for (const [typeName, typeDef] of Object.entries(CredentialTypes)) {
      const context = typeDef.context as string[];
      if (context.some((c) => c.includes(`/${sectorType?.toLowerCase()}/`) || c.includes('/federation/'))) {
        types.push(typeName);
      }
    }

    return types;
  }

  private isCredentialTypeSupported(credentialType: string): boolean {
    return this.getSupportedTypes().includes(credentialType);
  }

  private validateClaims(
    credentialType: string,
    claims: Record<string, unknown>
  ): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    const schema = CredentialTypes[credentialType as keyof typeof CredentialTypes]?.schema;

    if (!schema) {
      return { valid: false, errors: ['Unknown credential type'] };
    }

    for (const [field, def] of Object.entries(schema)) {
      const fieldDef = def as any;
      if (fieldDef.required && !(field in claims)) {
        errors.push(`Missing required field: ${field}`);
      }
    }

    return { valid: errors.length === 0, errors };
  }

  private getCrossDomainAcceptance(credentialType: string): string[] {
    const sectorType = this.config.sectorType?.toUpperCase() as keyof typeof CrossDomainMapping;
    const mapping = CrossDomainMapping[sectorType];
    if (!mapping) return [];

    const acceptedBy: string[] = [];
    for (const [domain, types] of Object.entries(mapping.providesTo)) {
      if ((types as string[]).includes(credentialType)) {
        acceptedBy.push(domain);
      }
    }

    return acceptedBy;
  }

  private generateCredentialOfferUri(offer: CredentialOffer): string {
    const credentialOffer = {
      credential_issuer: this.config.agentEndpoint,
      credentials: [offer.credentialType],
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': offer.preAuthorizedCode,
          user_pin_required: false,
        },
      },
    };

    const encodedOffer = encodeURIComponent(JSON.stringify(credentialOffer));
    return `openid-credential-offer://?credential_offer=${encodedOffer}`;
  }

  private async issueCredential(offer: CredentialOffer): Promise<string> {
    // Create W3C Verifiable Credential
    const now = new Date();
    const expirationDate = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000); // 1 year

    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        ...CredentialTypes[offer.credentialType as keyof typeof CredentialTypes]?.context || [],
      ],
      type: ['VerifiableCredential', offer.credentialType],
      id: `urn:uuid:${uuidv4()}`,
      issuer: {
        id: this.did,
        name: `${this.config.sectorType?.toUpperCase()} Sector Issuer`,
      },
      issuanceDate: now.toISOString(),
      expirationDate: expirationDate.toISOString(),
      credentialSubject: {
        id: offer.subjectDid,
        ...offer.claims,
      },
    };

    // In production, this would be a proper JWT-VC
    // For now, return a base64 encoded representation
    return Buffer.from(JSON.stringify(credential)).toString('base64');
  }

  private async verifyIssuerTrust(credentialType: string): Promise<boolean> {
    try {
      if (!this.config.fabricBridgeUrl) return true;

      const response = await axios.post(`${this.config.fabricBridgeUrl}/api/issuer/validate`, {
        issuerDid: this.did,
        credentialType,
      });

      return response.data.isValid === true;
    } catch (error) {
      logger.warn('Could not verify issuer trust, assuming trusted:', error);
      return true; // Fail open for development
    }
  }

  private async logCredentialIssuance(offer: CredentialOffer, credentialId: string): Promise<void> {
    try {
      if (!this.config.fabricBridgeUrl) return;

      await axios.post(`${this.config.fabricBridgeUrl}/api/audit/log`, {
        eventType: 'CREDENTIAL_ISSUED',
        issuerDid: this.did,
        subjectDid: offer.subjectDid,
        credentialType: offer.credentialType,
        credentialId,
        sectorType: this.config.sectorType,
      });
    } catch (error) {
      logger.warn('Failed to log credential issuance:', error);
    }
  }

  private async logCredentialRevocation(credentialId: string, reason: string): Promise<void> {
    try {
      if (!this.config.fabricBridgeUrl) return;

      await axios.post(`${this.config.fabricBridgeUrl}/api/audit/log`, {
        eventType: 'CREDENTIAL_REVOKED',
        issuerDid: this.did,
        credentialId,
        reason,
        sectorType: this.config.sectorType,
      });
    } catch (error) {
      logger.warn('Failed to log credential revocation:', error);
    }
  }
}
