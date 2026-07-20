CREATE TABLE IF NOT EXISTS api_clients (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    client_id VARCHAR(100) NOT NULL UNIQUE,
    client_secret_hash TEXT NOT NULL,
    owner_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'revoked')),
    scopes TEXT[] NOT NULL CHECK (
        cardinality(scopes) >= 1
        AND scopes <@ ARRAY[
            'secret:create',
            'secret:list',
            'secret:read-metadata',
            'secret:revoke',
            'dashboard:read'
        ]::TEXT[]
    ),
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_clients_status
    ON api_clients (status, expires_at);

CREATE INDEX IF NOT EXISTS idx_api_clients_owner
    ON api_clients (owner_user_id, created_at DESC);

CREATE OR REPLACE FUNCTION set_api_clients_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_api_clients_updated_at ON api_clients;
CREATE TRIGGER trg_api_clients_updated_at
BEFORE UPDATE ON api_clients
FOR EACH ROW
EXECUTE FUNCTION set_api_clients_updated_at();

ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_event_type_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_type_check CHECK (event_type IN (
    'secret.created',
    'secret.consumed',
    'secret.revoked',
    'secret.expired',
    'secret.password_failed',
    'auth.login_succeeded',
    'auth.login_failed',
    'auth.logout',
    'auth.password_changed',
    'user.created',
    'user.updated',
    'user.disabled',
    'user.enabled',
    'user.password_reset',
    'session.revoked',
    'api_client.created',
    'api_client.disabled',
    'api_client.enabled',
    'api_client.revoked',
    'api_client.secret_rotated'
));
