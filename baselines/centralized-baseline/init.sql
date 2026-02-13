-- Centralized Identity System Database Schema
-- For academic baseline comparison

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    domain VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Credentials table
CREATE TABLE IF NOT EXISTS credentials (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    credential_type VARCHAR(100) NOT NULL,
    issuer_domain VARCHAR(50) NOT NULL,
    claims JSONB NOT NULL,
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP
);

-- Cross-domain policies
CREATE TABLE IF NOT EXISTS cross_domain_policies (
    id UUID PRIMARY KEY,
    source_domain VARCHAR(50) NOT NULL,
    target_domain VARCHAR(50) NOT NULL,
    credential_type VARCHAR(100) NOT NULL,
    allowed BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(source_domain, target_domain, credential_type)
);

-- Verification logs
CREATE TABLE IF NOT EXISTS verification_logs (
    id UUID PRIMARY KEY,
    credential_id UUID REFERENCES credentials(id),
    verifier_domain VARCHAR(50) NOT NULL,
    verification_result BOOLEAN NOT NULL,
    verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    latency_ms INTEGER
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    token VARCHAR(500) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Trusted issuers
CREATE TABLE IF NOT EXISTS trusted_issuers (
    id UUID PRIMARY KEY,
    domain VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    credential_types TEXT[] NOT NULL,
    public_key TEXT,
    trust_level INTEGER DEFAULT 1,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert test users for benchmarking
INSERT INTO users (id, email, password_hash, full_name, domain) VALUES
    ('550e8400-e29b-41d4-a716-446655440000', 'test.finance@example.com', '$2b$10$test', 'Test Finance User', 'finance'),
    ('550e8400-e29b-41d4-a716-446655440001', 'test.health@example.com', '$2b$10$test', 'Test Health User', 'healthcare'),
    ('550e8400-e29b-41d4-a716-446655440002', 'test.edu@example.com', '$2b$10$test', 'Test Education User', 'education')
ON CONFLICT DO NOTHING;

-- Insert default cross-domain policies
INSERT INTO cross_domain_policies (id, source_domain, target_domain, credential_type, allowed) VALUES
    ('11111111-1111-1111-1111-111111111111', 'finance', 'healthcare', 'KYCCredential', TRUE),
    ('22222222-2222-2222-2222-222222222222', 'finance', 'healthcare', 'IncomeVerification', TRUE),
    ('33333333-3333-3333-3333-333333333333', 'education', 'finance', 'DiplomaCredential', TRUE),
    ('44444444-4444-4444-4444-444444444444', 'education', 'finance', 'TranscriptCredential', TRUE),
    ('55555555-5555-5555-5555-555555555555', 'healthcare', 'education', 'VaccinationCredential', TRUE),
    ('66666666-6666-6666-6666-666666666666', 'healthcare', 'education', 'MedicalClearance', TRUE)
ON CONFLICT DO NOTHING;

-- Insert default trusted issuers
INSERT INTO trusted_issuers (id, domain, name, credential_types, trust_level) VALUES
    ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'finance', 'Central Bank', ARRAY['KYCCredential', 'CreditScore', 'IncomeVerification'], 3),
    ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'healthcare', 'National Health Service', ARRAY['HealthInsurance', 'VaccinationCredential', 'MedicalClearance'], 3),
    ('cccccccc-cccc-cccc-cccc-cccccccccccc', 'education', 'Ministry of Education', ARRAY['DiplomaCredential', 'TranscriptCredential', 'Certificate'], 3)
ON CONFLICT DO NOTHING;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(credential_type);
CREATE INDEX IF NOT EXISTS idx_verification_logs_credential ON verification_logs(credential_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_policies_domains ON cross_domain_policies(source_domain, target_domain);
