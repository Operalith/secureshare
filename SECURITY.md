# Security

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

Security fixes are provided for the latest published release. Upgrade to the newest patch release before reporting an issue that may already be resolved.

## Reporting a Vulnerability

Do not disclose suspected vulnerabilities in a public GitHub issue, pull request, discussion, screenshot, or log excerpt.

Use [GitHub Private Vulnerability Reporting](https://github.com/Operalith/secureshare/security/advisories/new). Include the affected version, deployment model, impact, sanitized reproduction steps, and any suggested mitigation. Never include real secret payloads, raw one-time links, production credentials, Vault tokens, SMTP passwords, or session cookies.

Maintainers will acknowledge a complete report, investigate privately, coordinate remediation and release timing, and credit reporters when requested and appropriate.

## Security Architecture Summary

SecureShare stores Vault ciphertext and HMAC token lookups rather than plaintext payloads or raw tokens. Recipient links use fragments, reveal requires an explicit POST, and successful consumption is atomic. The backend briefly handles plaintext during Vault encryption and reveal, so SecureShare is not zero-knowledge or end-to-end encrypted.

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
- SMTP password ciphertext and decrypted SMTP password during send/test
- Rendered email content and recipient addresses
- Vault token and Transit key material
- PostgreSQL ciphertext and metadata

## Trust Boundaries

- Browser to app: recipient token is sent only in a POST body after fragment removal.
- App to PostgreSQL: stores metadata, token HMAC, status, and Vault ciphertext.
- App to Vault: sends plaintext for encryption and ciphertext for decryption.
- App to SMTP: sends only rendered one-time-link email, never secret payloads.
- Reverse proxy and APM: must not capture request or response bodies for sensitive endpoints.

## Token Security

Tokens are generated from 32 random bytes with `crypto/rand` and raw URL-safe base64 encoding. PostgreSQL stores only `HMAC-SHA256(token_pepper, raw_token)`. Tokens do not contain user names, merchant IDs, timestamps, UUID v1 values, or sequential data.

Rotating `TOKEN_HMAC_PEPPER` invalidates outstanding links.

## Vault Security

The application uses Vault Transit and the dedicated key `secureshare`. Plaintext is sent to Vault for encryption before database insert. Only Vault ciphertext is stored.

SMTP passwords are also encrypted with Vault Transit before PostgreSQL storage. The password is never returned through APIs, rendered back into HTML, logged, placed in audit metadata, or used as a metric label.

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
- `/api/v1/settings/email`
- `/api/v1/settings/email/send-test`
- `/api/v1/secret-links/send-email`

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

The recipient page reads `#<token>`, immediately replaces the URL with `/s`, and holds the raw token only in JavaScript memory until navigation, close, or refresh. This deliberately prevents durable browser history and storage from becoming another bearer-token repository. Refresh therefore shows the safe session-lost state and requires reopening the original link.

HTTPS and HSTS are mandatory in production.

Swagger UI is served from local assets only. It disables persisted authorization, does not prefill API client credentials, and uses the authenticated `/openapi.yaml` endpoint unless `OPENAPI_PUBLIC=true`.

Navigation visibility follows the session permission map but is not an authorization boundary. Every protected page and state-changing endpoint independently enforces its backend permission; authenticated forbidden pages return a 403 shell without exposing unauthorized items.

Browser regression tests use disposable QA identities and failure-only artifacts. Authenticated storage state, screenshots, traces, reports, and Node dependencies are Git-ignored and must never be published or attached without a redaction review.

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

Supported scopes are `secret:create`, `secret:list`, `secret:read-metadata`, `secret:revoke`, `secret:manage-protection`, `dashboard:read`, and `email:send`. API clients can be disabled, revoked, expired, and rotated. Basic auth is rejected in production unless the request is HTTPS or carries `X-Forwarded-Proto: https` from the trusted reverse proxy.

## Email Template and SMTP Security

Email delivery is optional and must be explicit per secret. SMTP settings are admin-only. Supported transport modes are `starttls`, `tls`, and development-only `none`; production rejects unencrypted SMTP and never skips certificate validation.

Templates are plain text with an allowlist of placeholders. The renderer rejects unknown placeholders, escapes HTML, and generates `text/plain` plus `text/html` bodies. It does not execute Go templates, functions, conditionals, loops, includes, JavaScript, forms, remote images, tracking pixels, external CSS, or external fonts.

Every delivered email contains the fragment-based one-time link and security context, but never the secret payload, link password, token hash, Vault ciphertext, SMTP credentials, API client secrets, or rendered body in audit metadata. Email scanners do not consume links because recipients still must POST through the Reveal action.

Historical email resend is unavailable because raw tokens are not stored. Immediate retry accepts the raw token only in a POST body while the creator page still holds it in memory; the token is not stored in localStorage, sessionStorage, cookies, PostgreSQL, or logs.

## Replay Prevention

The database enforces one-time reveal with an atomic `active` to `consuming` transition and a lease ID. Link passwords are verified before that lease is acquired. An incorrect password increments the failure counter atomically without entering `consuming`; attempts below the configured limit return `401 LINK_PASSWORD_INVALID`, while the locking attempt and later requests use the generic unavailable response. Only the lease owner can complete consumption. After successful decrypt, the app transitions to `consumed` and blanks ciphertext before returning plaintext.

The recipient page reads the raw token from `/s#<token>`, immediately removes the fragment from the address bar, and retains the token only in page memory. Password retries therefore work without navigation or reload. Refreshing the stripped URL intentionally loses access; the recipient must reopen the original link. SecureShare does not cache raw tokens in browser storage.

Link protection can be set, replaced, or removed only while a link is active, unconsumed, unexpired, and not revoked. Admins and scoped API clients may manage any link; developers may manage links they created; viewers are denied. Replacement writes a new Argon2id hash and resets failed attempts, removal clears the hash and counter, and neither operation changes or reconstructs the one-time URL. The current password is non-recoverable and is never returned by metadata, API, or HTML.

The public-experience preview is admin-only, uses fixed fake data, and does not create a delivery or token. Both supported locales use bundled application assets and the existing strict CSP; Persian uses the bundled Vazirmatn font and makes no external font request. Technical credential values are explicitly LTR-isolated inside the RTL document.

## Concurrency Handling

Concurrent reveal attempts against the same token can only acquire one consuming lease. Other requests receive generic unavailable responses while the lease is active. If Vault fails before delivery, the row is restored to `active` by the lease owner.

## Rate Limiting

The MVP includes in-memory fixed-window rate limiting:

- Login attempts per IP hash
- Secret creation per actor
- Token prepare per IP hash
- Consume attempts per IP hash and token hash
- Email delivery per authenticated actor
- Email retry per authenticated actor and token hash
- SMTP test email per admin

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

Audit events never store secret payloads, raw tokens, generated URLs, passwords, API keys, Authorization headers, Vault ciphertext, SMTP passwords, recipient emails, rendered email bodies, or full user agents. Retention is controlled by `AUDIT_EVENT_RETENTION`.

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
- Rate limits are in memory and are single-instance only.
- Local Compose uses Vault dev mode.
- Machine auth still supports the deprecated global admin API key while migrations to API clients complete.
- OIDC, LDAP, MFA, Redis-backed rate limiting, SMS OTP, and multi-tenant isolation are not implemented.
- Email is sent synchronously in v0.1.0; there is no queue, Redis worker, or historical resend without the raw token.
