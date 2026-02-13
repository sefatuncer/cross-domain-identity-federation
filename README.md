# Cross-Domain Identity Federation

Hyperledger Fabric + OpenID4VC hybrid solution for cross-sector credential verification.

## Overview

This system enables secure credential verification across different sectors (Finance, Healthcare, Education) by combining:

- **Hyperledger Fabric** - Permissioned blockchain for trust management
- **OpenID4VC** - Standard protocols for credential issuance/presentation

## Quick Start

```bash
# Start the network
docker-compose up -d

# Verify
curl http://localhost:4000/health
```

## Requirements

- Docker Desktop
- Node.js 18+
- Go 1.21+

## License

Apache 2.0
