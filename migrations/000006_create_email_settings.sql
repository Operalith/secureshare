CREATE TABLE IF NOT EXISTS email_settings (
    id UUID PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    smtp_host VARCHAR(255),
    smtp_port INTEGER,
    encryption_mode VARCHAR(20) NOT NULL DEFAULT 'starttls' CHECK (encryption_mode IN ('starttls', 'tls', 'none')),
    smtp_username VARCHAR(255),
    smtp_password_ciphertext TEXT,
    from_name VARCHAR(255),
    from_email VARCHAR(255),
    reply_to_email VARCHAR(255),
    connection_timeout_seconds INTEGER NOT NULL DEFAULT 5,
    send_timeout_seconds INTEGER NOT NULL DEFAULT 10,
    default_subject VARCHAR(255) NOT NULL,
    default_message TEXT NOT NULL,
    footer_text TEXT,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT email_settings_singleton CHECK (id = '00000000-0000-4000-8000-000000000001'::uuid),
    CONSTRAINT email_settings_port_check CHECK (smtp_port IS NULL OR (smtp_port >= 1 AND smtp_port <= 65535)),
    CONSTRAINT email_settings_timeouts_check CHECK (connection_timeout_seconds BETWEEN 1 AND 60 AND send_timeout_seconds BETWEEN 1 AND 120)
);

CREATE OR REPLACE FUNCTION set_email_settings_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_email_settings_updated_at ON email_settings;
CREATE TRIGGER trg_email_settings_updated_at
BEFORE UPDATE ON email_settings
FOR EACH ROW
EXECUTE FUNCTION set_email_settings_updated_at();

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
    'api_client.secret_rotated',
    'email.settings_updated',
    'email.password_updated',
    'email.password_cleared',
    'email.enabled',
    'email.disabled',
    'email.connection_test_succeeded',
    'email.connection_test_failed',
    'email.test_delivery_succeeded',
    'email.test_delivery_failed'
));
