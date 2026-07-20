CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    delivery_id UUID REFERENCES secret_deliveries(id) ON DELETE SET NULL,
    actor_id VARCHAR(255),
    event_type VARCHAR(64) NOT NULL CHECK (event_type IN (
        'secret.created',
        'secret.consumed',
        'secret.revoked',
        'secret.expired',
        'secret.password_failed',
        'auth.login_succeeded',
        'auth.login_failed'
    )),
    result VARCHAR(64) NOT NULL DEFAULT 'success',
    ip_hash VARCHAR(128),
    request_id VARCHAR(128),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_events_occurred_at
    ON audit_events (occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_delivery_id_occurred_at
    ON audit_events (delivery_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_type_occurred_at
    ON audit_events (event_type, occurred_at DESC);
