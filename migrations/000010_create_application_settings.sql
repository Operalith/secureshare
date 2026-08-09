CREATE TABLE IF NOT EXISTS application_settings (
    id UUID PRIMARY KEY,
    public_locale VARCHAR(10) NOT NULL DEFAULT 'en' CHECK (public_locale IN ('en', 'fa')),
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT application_settings_singleton CHECK (id = '00000000-0000-4000-8000-000000000002'::uuid)
);

INSERT INTO application_settings (id, public_locale)
VALUES ('00000000-0000-4000-8000-000000000002'::uuid, 'en')
ON CONFLICT (id) DO NOTHING;

CREATE OR REPLACE FUNCTION set_application_settings_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_application_settings_updated_at ON application_settings;
CREATE TRIGGER trg_application_settings_updated_at
BEFORE UPDATE ON application_settings
FOR EACH ROW
EXECUTE FUNCTION set_application_settings_updated_at();

ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_event_type_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_event_type_check CHECK (event_type IN (
    'secret.created',
    'secret.consumed',
    'secret.revoked',
    'secret.expired',
    'secret.password_failed',
    'secret.password_set',
    'secret.password_replaced',
    'secret.password_removed',
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
    'email.test_delivery_failed',
    'email.delivery_requested',
    'email.delivery_succeeded',
    'email.delivery_failed',
    'email.delivery_retry_requested',
    'email.delivery_retry_succeeded',
    'email.delivery_retry_failed',
    'email.template_override_used',
    'application.public_locale_updated'
));
