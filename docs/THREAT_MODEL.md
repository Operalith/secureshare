# Threat Model

SecureShare is an internal one-time secret delivery service for short-lived handoffs of credentials, tokens, configuration snippets, and similar sensitive values.

## Security Goals

- Prevent plaintext secret storage in PostgreSQL.
- Prevent raw token storage.
- Reveal each secret at most once.
- Return generic recipient errors for invalid, consumed, expired, revoked, locked, or unknown links.
- Keep admin and recipient UI free of historical secret contents.
- Avoid logging request bodies, response bodies, raw tokens, passwords, API keys, ciphertext, and Authorization headers.
- Keep observability low-cardinality and non-sensitive.

## Assets

- Plaintext secret payloads.
- Raw URL fragment tokens.
- Token HMAC pepper.
- Admin API key.
- Session and CSRF secrets.
- Request IP hash pepper.
- Optional link passwords and Argon2id hashes.
- Vault token and Transit key material.
- PostgreSQL ciphertext, metadata, and audit events.

## Trust Boundaries

- Admin browser to app: authenticated with session cookie and CSRF token.
- Machine API client to app: authenticated with scoped Basic auth API client credentials.
- Legacy automation to app: authenticated with the deprecated bearer admin API key while enabled.
- Recipient browser to app: possession of URL fragment token and optional password authorizes one reveal.
- App to PostgreSQL: metadata, token HMACs, state transitions, audit events, and Vault ciphertext.
- App to Vault: plaintext encryption and ciphertext decryption.
- Reverse proxy/APM/logging: trusted only if body capture and sensitive header logging are disabled.

## Main Abuse Cases

- Token guessing or enumeration.
- Link scanners loading recipient pages.
- Double-click or concurrent recipient reveal.
- Password brute force on protected links.
- Expired or revoked token probing.
- Vault outage during consume.
- Database outage during consume.
- Admin session CSRF.
- Admin API key brute force.
- API client credential brute force or leaked client secret.
- Request or response body capture by middleware, reverse proxies, APM, or logs.
- Public exposure of API metadata if `OPENAPI_PUBLIC=true` is enabled unintentionally.
- Insider access to PostgreSQL backups.

## Existing Controls

- 256-bit random tokens generated with `crypto/rand`.
- Raw tokens are placed in URL fragments and stripped from the recipient address bar.
- Token lookup stores only `HMAC-SHA256(token_pepper, raw_token)`.
- Vault Transit encrypts payloads before database insert.
- Atomic PostgreSQL transition from `active` to `consuming` with a lease ID.
- Only the lease owner can complete or restore consumption.
- Ciphertext is blanked on successful consume and revoke.
- Optional link passwords use Argon2id.
- Failed password attempts can revoke a delivery.
- Generic `SECRET_UNAVAILABLE` responses for recipient failures.
- Session cookies are HTTP-only and SameSite.
- Browser state-changing admin requests require CSRF tokens.
- Machine-authenticated Basic and legacy bearer requests are exempt from browser CSRF.
- API client secrets are shown only once, stored only as server-peppered HMACs, and can be disabled, revoked, expired, or rotated.
- OpenAPI and Swagger UI are authenticated by default and served from local assets with persisted authorization disabled.
- Login, create, prepare, and consume paths are rate-limited in memory.
- Security headers include no-store cache policy, no-referrer, CSP, frame denial, and nosniff.
- Structured request logging uses request ID, path, status, latency, and keyed IP hash only.
- Audit events store safe event types and safe metadata only.

## Residual Risks

- In-memory sessions and rate limits are single-instance.
- The deprecated global admin API key is less auditable than scoped API clients and should be disabled after migration.
- OIDC, SAML, and MFA are not implemented.
- Redis-backed shared rate limiting is not implemented.
- Local Compose uses Vault dev mode and must not be used for production secrets.
- Possession of an unprotected link is sufficient for reveal.
- The app cannot prevent a recipient from copying the revealed secret after successful delivery.
- PostgreSQL backups contain Vault ciphertext and metadata; they still require strong access control.

## Recommended Next Controls

- Add OIDC with individual admin identities and MFA.
- Move sessions to shared storage with server-side revocation.
- Move rate limits to Redis or a managed shared limiter.
- Add per-admin audit actor identity.
- Use platform-native Vault auth with short-lived renewable credentials.
- Add automated container and dependency scanning in CI.
- Add alert rules and a Grafana dashboard for the production metric set.
