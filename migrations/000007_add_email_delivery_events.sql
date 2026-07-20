ALTER TABLE api_clients DROP CONSTRAINT IF EXISTS api_clients_scopes_check;
ALTER TABLE api_clients ADD CONSTRAINT api_clients_scopes_check CHECK (
    cardinality(scopes) >= 1
    AND scopes <@ ARRAY[
        'secret:create',
        'secret:list',
        'secret:read-metadata',
        'secret:revoke',
        'dashboard:read',
        'email:send'
    ]::TEXT[]
);

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
    'email.test_delivery_failed',
    'email.delivery_requested',
    'email.delivery_succeeded',
    'email.delivery_failed',
    'email.delivery_retry_requested',
    'email.delivery_retry_succeeded',
    'email.delivery_retry_failed',
    'email.template_override_used'
));
