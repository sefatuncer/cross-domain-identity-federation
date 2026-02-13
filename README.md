# Cross-Domain Identity Federation

## Hyperledger Fabric + OpenID4VC Hybrid Solution

A hybrid identity federation system combining Hyperledger Fabric blockchain and OpenID4VC protocols for cross-domain credential recognition across Finance, Healthcare, and Education sectors.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Cross-Domain Identity Federation                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                   │
│  │   Finance    │    │  Healthcare  │    │  Education   │                   │
│  │   Sector     │    │   Sector     │    │   Sector     │                   │
│  │  (Org1)      │    │   (Org2)     │    │   (Org3)     │                   │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘                   │
│         │                   │                   │                            │
│         └───────────────────┼───────────────────┘                            │
│                             │                                                │
│                   ┌─────────▼─────────┐                                      │
│                   │   Bridge Service   │                                     │
│                   │   (Fabric-OpenID)  │                                     │
│                   └─────────┬─────────┘                                      │
│                             │                                                │
│         ┌───────────────────┴───────────────────┐                            │
│         │                                       │                            │
│  ┌──────▼──────┐                       ┌───────▼───────┐                    │
│  │ Hyperledger │                       │   OpenID4VC   │                    │
│  │   Fabric    │                       │    Agents     │                    │
│  │  Network    │                       │               │                    │
│  │             │                       │ • Issuers     │                    │
│  │ • Trusted   │                       │ • Holders     │                    │
│  │   Issuer    │                       │ • Verifiers   │                    │
│  │   Registry  │                       │               │                    │
│  │ • Schema    │                       └───────────────┘                    │
│  │   Registry  │                                                            │
│  │ • Policy    │                                                            │
│  │   Engine    │                                                            │
│  │ • Audit Log │                                                            │
│  └─────────────┘                                                            │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Features

- **Trusted Issuer Registry**: Blockchain-based registry of trusted credential issuers
- **Credential Schema Registry**: Standardized credential schemas for each sector
- **Cross-Domain Policy Engine**: Configurable policies for cross-domain credential acceptance
- **Privacy-Preserving Audit**: GDPR-compliant audit logging with anonymization
- **OpenID4VCI/VP Support**: Standard-compliant credential issuance and presentation
- **Multi-Sector Support**: Finance, Healthcare, and Education domains

## Quick Start

### Prerequisites

- Docker Desktop
- Node.js 18+
- Go 1.21+ (for chaincode development)

### Start the Network

**Windows (PowerShell):**
```powershell
.\scripts\start-network.ps1 -Command start
```

**Linux/macOS:**
```bash
./scripts/start-network.sh start
```

### Verify Installation

```bash
# Health check
curl http://localhost:4000/health

# Check cross-domain mappings
curl http://localhost:4000/api/cross-domain/mappings
```

## Project Structure

```
cross-domain-identity-federation/
├── docker-compose.yml           # Docker Compose orchestration
├── fabric-network/              # Hyperledger Fabric configuration
│   ├── chaincode/               # Smart contracts (Go)
│   │   ├── trusted-issuer-registry/
│   │   ├── credential-schema-registry/
│   │   ├── cross-domain-policy/
│   │   └── privacy-audit/
│   ├── organizations/           # MSP configurations
│   └── channels/                # Channel configurations
├── openid4vc/                   # OpenID4VC agents (TypeScript)
│   ├── src/
│   │   ├── agents/              # Agent implementations
│   │   │   ├── IssuerAgent.ts
│   │   │   ├── HolderAgent.ts
│   │   │   └── VerifierAgent.ts
│   │   └── config/              # Configuration
│   └── Dockerfile
├── bridge-service/              # Fabric-OpenID bridge (TypeScript)
│   ├── src/
│   │   ├── services/
│   │   └── index.ts
│   └── Dockerfile
├── tests/                       # Test suites
│   ├── integration/
│   └── benchmark/
├── scripts/                     # Utility scripts
└── docs/                        # Documentation and paper
```

## API Reference

### Bridge Service (Port 4000)

#### Issuer Validation
```bash
POST /api/issuer/validate
{
  "issuerDid": "did:web:bank.finance.crossdomain.com",
  "credentialType": "KYCCredential"
}
```

#### Policy Evaluation
```bash
POST /api/policy/evaluate
{
  "credentialType": "KYCCredential",
  "sourceDomain": "FINANCE",
  "targetDomain": "HEALTHCARE",
  "issuerTrustLevel": 5,
  "availableAttributes": ["fullName", "dateOfBirth"]
}
```

#### Cross-Domain Verification
```bash
POST /api/cross-domain/verify
{
  "sourceDomain": "FINANCE",
  "targetDomain": "HEALTHCARE",
  "credentialType": "KYCCredential",
  "issuerDid": "did:web:bank.finance.crossdomain.com"
}
```

### Issuer Agents (Ports 3001-3003)

#### Create Credential Offer
```bash
POST /credentials/offer
{
  "credentialType": "KYCCredential",
  "subjectDid": "did:key:z6Mk...",
  "claims": {
    "fullName": "John Doe",
    "dateOfBirth": "1990-01-15"
  }
}
```

#### OpenID4VCI Endpoints
- `GET /.well-known/openid-credential-issuer` - Issuer metadata
- `POST /credentials/token` - Token endpoint
- `POST /credentials/credential` - Credential endpoint

### Verifier Agent (Port 3020)

#### Create Verification Request
```bash
POST /verifier/request
{
  "credentialTypes": ["KYCCredential"],
  "purpose": "Hospital registration",
  "sourceDomain": "FINANCE",
  "targetDomain": "HEALTHCARE"
}
```

#### Cross-Domain Verification
```bash
POST /verifier/cross-domain/verify
{
  "presentation": {...},
  "sourceDomain": "FINANCE",
  "targetDomain": "HEALTHCARE"
}
```

## Cross-Domain Credential Mapping

| Source Domain | Target Domain | Accepted Credential Types |
|--------------|---------------|--------------------------|
| Finance | Healthcare | KYCCredential, IncomeVerificationCredential |
| Finance | Education | KYCCredential |
| Healthcare | Finance | HealthInsuranceCredential |
| Healthcare | Education | VaccinationCredential, MedicalClearanceCredential |
| Education | Finance | DiplomaCredential, TranscriptCredential, CertificateCredential |
| Education | Healthcare | DiplomaCredential, CertificateCredential |

## Running Tests

### Integration Tests
```bash
cd tests/integration
npx ts-node cross-domain-scenarios.test.ts
```

### Performance Benchmarks
```bash
cd tests/benchmark
npx ts-node performance-benchmark.ts
```

## Smart Contracts

### Trusted Issuer Registry
- `RegisterIssuer`: Register a new trusted issuer
- `ValidateIssuer`: Validate issuer for credential type
- `RevokeIssuer`: Revoke issuer status
- `GetIssuersByType`: Query issuers by sector

### Cross-Domain Policy
- `RegisterPolicy`: Create cross-domain acceptance policy
- `EvaluatePolicy`: Evaluate credential against policy
- `GetAcceptedCredentialTypes`: Get accepted types between domains
- `LogCrossDomainVerification`: Log verification events

### Privacy Audit
- `LogVerificationEvent`: Log privacy-preserving audit event
- `QueryAuditLog`: Query audit events
- `GenerateComplianceReport`: Generate compliance reports
- `RecordConsent`: Record user consent

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Bridge service port | 4000 |
| `FABRIC_GATEWAY_HOST` | Fabric peer host | localhost |
| `FABRIC_CHANNEL_NAME` | Main channel name | global-channel |
| `OPENID_FINANCE_ISSUER` | Finance issuer URL | http://localhost:3001 |
| `OPENID_HEALTHCARE_ISSUER` | Healthcare issuer URL | http://localhost:3002 |
| `OPENID_EDUCATION_ISSUER` | Education issuer URL | http://localhost:3003 |

## Benchmark Results

Results from 100 test runs per scenario comparing our solution against baselines:

### Latency Comparison (ms)

| Operation | Our Solution | OIDC Federation | Centralized | Indy |
|-----------|--------------|-----------------|-------------|------|
| Credential Issuance (Mean) | **4.38** | 41.09 | 2.75 | 1087.50 |
| Credential Issuance (P95) | **7.00** | 57.00 | 4.00 | 1289.00 |
| Cross-Domain Verify (Mean) | **3.27** | 41.29 | N/A | N/A |
| Full Flow (Mean) | **2.70** | 75.38 | 5.46 | 1092.81 |
| Full Flow (P95) | **4.00** | 97.00 | 7.00 | 1303.50 |

### Statistical Significance

All improvements are statistically significant:
- vs OIDC: p < 0.0001, Cohen's d = -8.05 (large effect) - **96.4% faster**
- vs Centralized: p < 0.0001, Cohen's d = -2.37 (large effect) - **50.5% faster**
- vs Indy: p < 0.0001, Cohen's d = -11.72 (large effect) - **99.8% faster**

### Security Features Comparison

| Feature | Our Solution | OIDC | Centralized | Indy |
|---------|--------------|------|-------------|------|
| Decentralized Trust | ✓ | ✗ | ✗ | ✓ |
| Tamper Resistance | ✓ | ✗ | ✗ | ✓ |
| Selective Disclosure | ✓ | ✗ | ✗ | ✓ |
| Standard Compliance | ✓ | Partial | ✗ | ✗ |
| Cross-Domain Policy | ✓ | ✗ | ✗ | ✗ |
| Privacy-Preserving Audit | ✓ | ✗ | ✗ | ✗ |

## Citation

If you use this work, please cite:

```bibtex
@article{tuncer2026crossdomain,
  title={Cross-Domain Identity Federation using Hyperledger Fabric and OpenID for Verifiable Credentials},
  author={Tuncer, Sefa},
  journal={Blockchain: Research and Applications},
  year={2026},
  publisher={Elsevier}
}
```

## License

This project is licensed under the Apache 2.0 License.

## Author

**Sefa Tunçer**

## References

- [Hyperledger Fabric Documentation](https://hyperledger-fabric.readthedocs.io/)
- [OpenID for Verifiable Credentials](https://openid.net/sg/openid4vc/)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
- [Credo (Aries Framework JavaScript)](https://credo.js.org/)
