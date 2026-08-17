# Changelog

All notable changes to SecureShare are documented in this file.

The format is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-17

### Added

- One-time secret links with explicit reveal, expiration, revocation, and atomic consumption.
- Structured credentials, text, JSON, and configuration payloads encrypted with HashiCorp Vault Transit.
- Optional Argon2id link passwords with configurable failed-attempt limits.
- PostgreSQL-backed users, roles, sessions, scoped API clients, and server-side theme preferences.
- Optional SMTP link delivery with encrypted settings and safe customizable templates.
- OpenAPI 3.1, local Swagger UI, Prometheus metrics, health checks, and public build metadata.
- Responsive server-rendered administration and recipient interfaces with light and dark themes.

### Security

- Raw link tokens are retained only in URL fragments and browser page memory.
- PostgreSQL stores HMAC token lookups and Vault ciphertext, not raw tokens or plaintext payloads.
- Recipient pages require an explicit POST reveal and use no-store cache headers and a strict CSP.
- Sensitive request/response bodies, credentials, raw links, and Authorization headers are excluded from application logs.
- Security tests cover authorization, CSRF, payload limits, replay prevention, concurrency, cache controls, and log canaries.

### Developer Experience

- Scoped API clients and examples for cURL, Go, Python, JavaScript, and Postman.
- Isolated Docker-backed smoke, integration, security, regression, and browser test targets.
- GitHub Actions CI, Dependabot configuration, and issue and pull-request templates.

### Operations

- Docker Compose configurations for local development and production-oriented deployment.
- Vault bootstrap for local Transit development, cleanup retention controls, audit events, and readiness checks.
- Deployment, operations, threat-model, production-checklist, and recovery documentation.

### Localization

- Complete English and Persian recipient experiences.
- RTL Persian layout with bundled Vazirmatn and LTR-isolated technical values.
- Browser-local Gregorian dates in English and Jalali dates in Persian.

### Known Limitations

- Local Compose uses Vault dev mode.
- SMTP delivery is synchronous.
- Rate limiting is in-memory and not coordinated across instances.
- Multi-instance production requires shared rate limiting and session storage.
- Historical email resend is unavailable because raw link tokens are not stored.
- SSO, LDAP, MFA, SMS OTP, asynchronous delivery queues, and multi-tenant isolation are not included.

[0.1.0]: https://github.com/Operalith/secureshare/releases/tag/v0.1.0
