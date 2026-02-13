import { getAgentConfig } from './config/agent.config.js';
import { IssuerAgent } from './agents/IssuerAgent.js';
import { HolderAgent } from './agents/HolderAgent.js';
import { VerifierAgent } from './agents/VerifierAgent.js';
import { logger } from './agents/BaseAgent.js';

async function main() {
  const config = getAgentConfig();

  logger.info(`Starting ${config.agentType} agent: ${config.agentName}`);
  logger.info(`Sector: ${config.sectorType || 'Not specified'}`);
  logger.info(`Port: ${config.agentPort}`);
  logger.info(`Endpoint: ${config.agentEndpoint}`);

  let agent;

  switch (config.agentType) {
    case 'issuer':
      agent = new IssuerAgent(config);
      break;
    case 'holder':
      agent = new HolderAgent(config);
      break;
    case 'verifier':
      agent = new VerifierAgent(config);
      break;
    default:
      throw new Error(`Unknown agent type: ${config.agentType}`);
  }

  try {
    await agent.start();
    logger.info(`${config.agentType.toUpperCase()} agent started successfully`);
    logger.info(`Health check: ${config.agentEndpoint}/health`);
    logger.info(`Agent info: ${config.agentEndpoint}/info`);

    // Handle graceful shutdown
    process.on('SIGTERM', () => {
      logger.info('Received SIGTERM, shutting down gracefully...');
      process.exit(0);
    });

    process.on('SIGINT', () => {
      logger.info('Received SIGINT, shutting down gracefully...');
      process.exit(0);
    });
  } catch (error) {
    logger.error('Failed to start agent:', error);
    process.exit(1);
  }
}

main();

export { IssuerAgent, HolderAgent, VerifierAgent };
export * from './config/agent.config.js';
