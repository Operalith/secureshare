# Security

## Threat Model

SecureShare protects sensitive values during internal handoff to recipients. It assumes the app, PostgreSQL, and Vault run in a trusted private environment behind an authenticated internal boundary. The recipient reveal endpoint is intentionally unauthenticated because possession of the link token, and optional password, authorizes a one-time reveal.

## Protected Assets

- Plaintext secret payloads
- Raw URL fragment tokens
- Token HMAC pepper
- Admin API key
- Session secret
- CSRF secret
- Request IP hash pepper
- API client secrets
- Optional link passwords
- Vault token and Transit key material
- PostgreSQL ciphertext and metadata

## Trust Boundaries

- Browser to app: recipient token is sent only in a POST body after fragment removal.
- App to PostgreSQL: stores metadata, token HMAC, status, and Vault ciphertext.
- App to Vault: sends plaintext for encryption and ciphertext for decryption.
- Reverse proxy and APM: must not capture request or response bodies for sensitive endpoints.

## Token Security

Tokens are generated from 32 random bytes with `crypto/rand` and raw URL-safe base64 encoding. PostgreSQL stores only `HMAC-SHA256(token_pepper, raw_token)`. Tokens do not contain user names, merchant IDs, timestamps, UUID v1 values, or sequential data.

Rotating `TOKEN_HMAC_PEPPER` invalidates outstanding links.

## Vault Security

The application uses Vault Transit and the dedicated key `secureshare`. Plaintext is sent to Vault for encryption before database insert. Only Vault ciphertext is stored.

Production requirements:

- Persistent initialized and unsealed Vault cluster
- AppRole, Kubernetes Auth, or another managed auth method
- Short-lived Vault tokens
- Vault audit devices
- Network policy that permits only the app to reach required Vault endpoints
- Documented Transit key rotation and restore process
- Least-privilege policy matching `deploy/vault/secureshare-policy.hcl`

## Database Security

PostgreSQL stores no plaintext secrets and no raw tokens. Payload retention cleanup blanks ciphertext after consumption and after configurable retention for expired or revoked records.

Use PostgreSQL TLS, encrypted storage, least-privilege database credentials, audited backups, and restricted administrative access in production.

## Logging Redaction

The app uses structured JSON logs and records only safe metadata: request ID, method, path, status, latency, and a keyed IP hash. It does not log request bodies, response bodies, raw tokens, full secret URLs, Authorization headers, API keys, passwords, Vault ciphertext, or plaintext payloads.

Reverse proxies, WAFs, APM tools, and trace collectors must disable request and response body capture for:

- `/api/v1/secret-links`
- `/api/v1/secret-links/prepare`
- `/api/v1/secret-links/consume`
- `/api/v1/auth/login`

## Browser Protections

Secret pages and API responses include:

- `Cache-Control: no-store, private, max-age=0`
- `Pragma: no-cache`
- `Expires: 0`
- `Referrer-Policy: no-referrer`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- Strict Content Security Policy
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

The frontend does not use localStorage, sessionStorage, IndexedDB, cookies, service worker cache, query parameters, external scripts, external fonts, analytics, or persisted frontend state for secrets.

HTTPS and HSTS are mandatory in production.

Swagger UI is served from local assets only. It disables persisted authorization, does not prefill API client credentials, and uses the authenticated `/openapi.yaml` endpoint unless `OPENAPI_PUBLIC=true`.

## Admin Users, Session and CSRF

The browser admin UI uses local PostgreSQL users and opaque HTTP-only SameSite cookies. Only a keyed session-token hash is stored in PostgreSQL. Session TTL, idle timeout, secure cookie behavior, and CSRF signing are configured with `SESSION_TTL`, `SESSION_IDLE_TIMEOUT`, `COOKIE_SECURE`, and `CSRF_SECRET`.

The bootstrap administrator is created only when no users exist. Remove `BOOTSTRAP_ADMIN_PASSWORD` from production runtime configuration after initial setup.

All authenticated browser state-changing actions require CSRF validation:

- Create secret
- Revoke secret
- Manual cleanup
- Logout

Machine-authenticated Basic and legacy bearer requests do not use browser CSRF protection. The global admin API key is retained for compatibility, can be disabled with `LEGACY_ADMIN_API_KEY_ENABLED=false`, and is deprecated for new integrations.

## API Client Authentication

API clients authenticate with HTTP Basic auth using `client_id:client_secret`. Client secrets are generated with cryptographically secure randomness, shown only at creation or rotation, and stored only as `HMAC-SHA256(TOKEN_HMAC_PEPPER, client_id || client_secret)`.

Supported scopes are `secret:create`, `secret:list`, `secret:read-metadata`, `secret:revoke`, and `dashboard:read`. API clients can be disabled, revoked, expired, and rotated. Basic auth is rejected in production unless the request is HTTPS or carries `X-Forwarded-Proto: https` from the trusted reverse proxy.

## Replay Prevention

The database enforces one-time reveal with an atomic `active` to `consuming` transition and a lease ID. Only the lease owner can complete consumption. After successful decrypt, the app transitions to `consumed` and blanks ciphertext before returning plaintext.

## Concurrency Handling

Concurrent reveal attempts against the same token can only acquire one consuming lease. Other requests receive generic unavailable responses while the lease is active. If Vault fails before delivery, the row is restored to `active` by the lease owner.

## Rate Limiting

The MVP includes in-memory fixed-window rate limiting:

- Login attempts per IP hash
- Secret creation per actor
- Token prepare per IP hash
- Consume attempts per IP hash and token hash

Use Redis or another shared limiter before running multiple app replicas.

## Audit Events

Audit events store only safe metadata:

- Event type
- Result
- Optional delivery ID
- Actor ID
- Hashed IP
- Request ID
- Timestamp

Audit events never store secret payloads, raw tokens, generated URLs, passwords, API keys, Authorization headers, Vault ciphertext, or full user agents. Retention is controlled by `AUDIT_EVENT_RETENTION`.

## Secret Lifecycle

Defaults:

- Maximum TTL: 7 days
- Default TTL: 24 hours
- Consuming lease: 30 seconds
- Consumed payload retention: 0 minutes
- Expired payload retention: 24 hours
- Revoked payload retention: 24 hours
- Cleanup interval: 5 minutes

## Production Hardening Checklist

Use `docs/PRODUCTION_CHECKLIST.md` as the deployment gate. At minimum:

- Enforce HTTPS and HSTS.
- Set `APP_ENV=production` and `COOKIE_SECURE=true`.
- Use a production Vault cluster, not dev mode.
- Use short-lived Vault auth.
- Enable Vault audit devices.
- Enable PostgreSQL TLS and encrypted backups.
- Generate strong environment secrets.
- Use external session storage for multiple replicas.
- Use Redis-backed rate limiting for multiple replicas.
- Disable request and response body logging everywhere.
- Redact sensitive paths in APM and reverse proxies.
- Restrict container egress to PostgreSQL and Vault.
- Run non-root containers with no-new-privileges.
- Apply resource limits and image scanning.
- Ship audit logs to a protected sink.
- Test restore from PostgreSQL and Vault backups.
- Run `make security-test` against the deployment.

## Incident Response Notes

If a token pepper, admin API key, session secret, or Vault credential is exposed:

1. Rotate the exposed value immediately.
2. Revoke active sessions.
3. Revoke or expire active secret deliveries if token exposure is possible.
4. Review structured logs and Vault audit logs.
5. Rotate affected merchant credentials or API keys.
6. Preserve evidence according to internal incident policy.

## Key Rotation Process

Vault Transit key rotation should use Vault-native rotation. Existing ciphertext remains decryptable by Vault. Token pepper rotation invalidates outstanding links and should be treated as a deliberate emergency or maintenance action.

## Security Limitations

- Link possession authorizes reveal unless optional password protection is enabled.
- In-memory sessions and rate limits are single-instance only.
- Local Compose uses Vault dev mode.
- Machine auth still supports the deprecated global admin API key while migrations to API clients complete.
- OIDC, Redis-backed rate limiting, and shared session storage are not implemented.
