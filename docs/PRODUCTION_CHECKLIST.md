# Production Checklist

Use this checklist before exposing SecureShare outside a local development environment.

## Required Controls

- [ ] HTTPS enabled at the public reverse proxy.
- [ ] HSTS enabled with an appropriate preload decision for the domain.
- [ ] `APP_ENV=production`.
- [ ] `COOKIE_SECURE=true`.
- [ ] `APP_BASE_URL` uses the public `https://` origin.
- [ ] Strong `SECURESHARE_ADMIN_API_KEY` generated and stored in the secret manager for temporary legacy compatibility.
- [ ] Scoped API clients created for integrations.
- [ ] `LEGACY_ADMIN_API_KEY_ENABLED=false` after legacy integrations migrate.
- [ ] Strong `TOKEN_HMAC_PEPPER` generated, backed up securely, and access-restricted.
- [ ] Strong `SESSION_SECRET` generated and stored in the secret manager.
- [ ] Strong `CSRF_SECRET` generated and stored in the secret manager.
- [ ] Strong `REQUEST_IP_HASH_PEPPER` generated and stored in the secret manager.
- [ ] Production Vault configured; Vault dev mode is not used.
- [ ] Vault Transit engine enabled and `secureshare` key created.
- [ ] Vault policy grants only encrypt, decrypt, and key read for the Transit key.
- [ ] Vault audit enabled and shipped to a protected sink.
- [ ] Vault authentication uses AppRole, Kubernetes Auth, or equivalent short-lived credentials.
- [ ] Vault token renewal and expiry monitoring are configured.
- [ ] PostgreSQL TLS enabled.
- [ ] PostgreSQL least-privilege application role configured.
- [ ] PostgreSQL backups scheduled.
- [ ] PostgreSQL restore tested.
- [ ] Reverse proxy token redaction verified.
- [ ] Request body logging disabled in proxy, WAF, APM, tracing, and log processors.
- [ ] Response body logging disabled in proxy, WAF, APM, tracing, and log processors.
- [ ] APM body capture disabled for all SecureShare routes.
- [ ] Access logs do not include `Authorization`, request bodies, response bodies, raw tokens, or generated URLs.
- [ ] Cleanup verified with consumed, expired, revoked, and stale-consuming rows.
- [ ] Security test passed: `make security-test`.
- [ ] Concurrency test passed through integration tests.
- [ ] Container images scanned.
- [ ] Admin API key rotated from bootstrap value or disabled after API client migration.
- [ ] Session secrets rotated from bootstrap value.
- [ ] Token pepper backed up securely and excluded from routine rotation.
- [ ] Monitoring alerts configured for readiness, Vault errors, latency, rate limits, login failures, CSRF failures, cleanup duration, and active link spikes.

## Deployment Gate

Before promoting a new image:

```bash
go test ./...
go vet ./...
make lint
make smoke
make integration-test
make security-test
docker compose config
```

After promotion:

```bash
curl -fsS https://secureshare.example.com/health/ready
curl -fsS https://secureshare.example.com/metrics
```

Inspect application, reverse proxy, Vault audit, and APM logs for the known canary values used by `scripts/security-test.sh`. No canary secret, raw token, API key, password, Vault ciphertext, or Authorization header should appear.

## Explicit MVP Limits

- Sessions are in memory and are single-instance.
- Rate limiting is in memory and is single-instance.
- Machine authentication supports scoped API clients; the deprecated global admin API key may remain enabled during migration.
- OIDC and SSO are not implemented.
- Redis-backed shared limiter and session storage are not implemented.
- Horizontal app replicas require shared session storage and shared rate limiting first.
