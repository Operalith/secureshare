CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS secret_deliveries (
    id UUID PRIMARY KEY,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    encrypted_payload TEXT NOT NULL,
    title VARCHAR(255),
    description TEXT CHECK (description IS NULL OR char_length(description) <= 2000),
    recipient_reference VARCHAR(255),
    status VARCHAR(20) NOT NULL CHECK (status IN ('active', 'consuming', 'consumed', 'expired', 'revoked')),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    consuming_started_at TIMESTAMPTZ,
    consuming_lease_id UUID,
    password_hash TEXT,
    failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    max_failed_attempts INTEGER NOT NULL DEFAULT 5 CHECK (max_failed_attempts BETWEEN 1 AND 20),
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT consumed_requires_timestamp CHECK (status <> 'consumed' OR consumed_at IS NOT NULL),
    CONSTRAINT revoked_requires_timestamp CHECK (status <> 'revoked' OR revoked_at IS NOT NULL),
    CONSTRAINT consuming_requires_lease CHECK (status <> 'consuming' OR (consuming_started_at IS NOT NULL AND consuming_lease_id IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_secret_deliveries_status_expires
    ON secret_deliveries (status, expires_at);

CREATE INDEX IF NOT EXISTS idx_secret_deliveries_cleanup
    ON secret_deliveries (status, updated_at);

CREATE INDEX IF NOT EXISTS idx_secret_deliveries_consuming_lease
    ON secret_deliveries (status, consuming_started_at)
    WHERE status = 'consuming';

CREATE INDEX IF NOT EXISTS idx_secret_deliveries_created_by
    ON secret_deliveries (created_by, created_at DESC);

CREATE OR REPLACE FUNCTION set_secret_deliveries_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_secret_deliveries_updated_at ON secret_deliveries;
CREATE TRIGGER trg_secret_deliveries_updated_at
BEFORE UPDATE ON secret_deliveries
FOR EACH ROW
EXECUTE FUNCTION set_secret_deliveries_updated_at();
