import {
  Agent,
  InitConfig,
  DidsModule,
  KeyType,
  TypedArrayEncoder,
  CredentialsModule,
  V2CredentialProtocol,
  ProofsModule,
  V2ProofProtocol,
  ConnectionsModule,
  AutoAcceptCredential,
  AutoAcceptProof,
  JsonLdCredentialFormatService,
  W3cCredentialsModule,
} from '@credo-ts/core';
import { agentDependencies, HttpInboundTransport } from '@credo-ts/node';
import { AskarModule } from '@credo-ts/askar';
import { ariesAskar } from '@hyperledger/aries-askar-nodejs';
import {
  OpenId4VcIssuerModule,
  OpenId4VcVerifierModule,
  OpenId4VcHolderModule,
} from '@credo-ts/openid4vc';
import express, { Express, Request, Response } from 'express';
import cors from 'cors';
import { v4 as uuidv4 } from 'uuid';
import winston from 'winston';

import { AgentConfig, getInitConfig } from '../config/agent.config.js';

// Logger setup
export const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
  ],
});

export abstract class BaseAgent {
  protected agent!: Agent;
  protected config: AgentConfig;
  protected app: Express;
  protected did?: string;
  protected verificationMethod?: string;

  constructor(config: AgentConfig) {
    this.config = config;
    this.app = express();
    this.setupExpress();
  }

  private setupExpress(): void {
    this.app.use(cors());
    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: true }));

    // Health check endpoint
    this.app.get('/health', (req: Request, res: Response) => {
      res.json({
        status: 'healthy',
        agentName: this.config.agentName,
        agentType: this.config.agentType,
        sectorType: this.config.sectorType,
        did: this.did,
        timestamp: new Date().toISOString(),
      });
    });

    // Agent info endpoint
    this.app.get('/info', async (req: Request, res: Response) => {
      try {
        const info = await this.getAgentInfo();
        res.json(info);
      } catch (error) {
        res.status(500).json({ error: 'Failed to get agent info' });
      }
    });
  }

  protected async createAgent(): Promise<Agent> {
    const initConfig = getInitConfig(this.config);

    const agent = new Agent({
      config: initConfig,
      dependencies: agentDependencies,
      modules: this.getAgentModules(),
    });

    return agent;
  }

  protected getAgentModules(): Record<string, unknown> {
    const baseModules = {
      askar: new AskarModule({ ariesAskar }),
      dids: new DidsModule({
        registrars: [],
        resolvers: [],
      }),
      connections: new ConnectionsModule({
        autoAcceptConnections: true,
      }),
      credentials: new CredentialsModule({
        autoAcceptCredentials: AutoAcceptCredential.ContentApproved,
        credentialProtocols: [new V2CredentialProtocol({})],
      }),
      proofs: new ProofsModule({
        autoAcceptProofs: AutoAcceptProof.ContentApproved,
        proofProtocols: [new V2ProofProtocol({})],
      }),
      w3cCredentials: new W3cCredentialsModule(),
    };

    return baseModules;
  }

  async initialize(): Promise<void> {
    logger.info(`Initializing ${this.config.agentType} agent: ${this.config.agentName}`);

    this.agent = await this.createAgent();

    // Register HTTP transport
    const httpInboundTransport = new HttpInboundTransport({
      port: this.config.agentPort,
      app: this.app,
    });
    this.agent.registerInboundTransport(httpInboundTransport);

    await this.agent.initialize();

    // Create or retrieve DID
    await this.setupDid();

    // Setup agent-specific routes
    this.setupRoutes();

    logger.info(`Agent ${this.config.agentName} initialized with DID: ${this.did}`);
  }

  protected async setupDid(): Promise<void> {
    // Check if we already have a DID
    const dids = await this.agent.dids.getCreatedDids({ method: 'key' });

    if (dids.length > 0) {
      this.did = dids[0].did;
      this.verificationMethod = dids[0].didDocument?.verificationMethod?.[0]?.id;
    } else {
      // Create a new did:key
      const didResult = await this.agent.dids.create({
        method: 'key',
        options: {
          keyType: KeyType.Ed25519,
        },
      });

      this.did = didResult.didState.did;
      this.verificationMethod = didResult.didState.didDocument?.verificationMethod?.[0]?.id;
    }
  }

  protected abstract setupRoutes(): void;

  async getAgentInfo(): Promise<Record<string, unknown>> {
    return {
      agentName: this.config.agentName,
      agentType: this.config.agentType,
      sectorType: this.config.sectorType,
      did: this.did,
      verificationMethod: this.verificationMethod,
      endpoint: this.config.agentEndpoint,
      isInitialized: this.agent?.isInitialized ?? false,
    };
  }

  async start(): Promise<void> {
    await this.initialize();
    logger.info(`Agent ${this.config.agentName} started on port ${this.config.agentPort}`);
  }

  getApp(): Express {
    return this.app;
  }

  getAgent(): Agent {
    return this.agent;
  }

  getDid(): string | undefined {
    return this.did;
  }
}
