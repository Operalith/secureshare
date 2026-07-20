# Operations

## Environment Variables

See `.env.example` for the full local configuration.

Important values:

- `APP_BASE_URL`: public URL used to build secret links.
- `DATABASE_URL`: PostgreSQL connection string.
- `VAULT_ADDR`: Vault API address.
- `VAULT_TOKEN`: local dev token or production auth token.
- `VAULT_TRANSIT_KEY`: default `secureshare`.
- `SECURESHARE_ADMIN_API_KEY`: deprecated legacy internal management credential.
- `LEGACY_ADMIN_API_KEY_ENABLED`: set `false` after integrations move to API clients.
- `TOKEN_HMAC_PEPPER`: HMAC key for token lookup hashes.
- `SESSION_SECRET`: signs session cookie IDs.
- `CSRF_SECRET`: signs session-bound CSRF tokens.
- `SESSION_TTL`: absolute session lifetime.
- `SESSION_IDLE_TIMEOUT`: idle session lifetime.
- `COOKIE_SECURE`: must be `true` outside development.
- `REQUEST_IP_HASH_PEPPER`: hashes client IPs for logs and rate limits.
- `MAX_SECRET_TTL`: maximum allowed expiration, default `168h`.
- `DEFAULT_SECRET_TTL`: default expiration, default `24h`.
- `CONSUMING_LEASE_TTL`: active consuming lease duration.
- `CLEANUP_INTERVAL`: background cleanup cadence.
- `OPENAPI_PUBLIC`: exposes `/openapi.yaml` and `/docs` without login when true.
- `SWAGGER_UI_ENABLED`: serves the local Swagger UI at `/docs` when true.

Outside development, startup fails for weak admin keys, token peppers, session secrets, CSRF secrets, and insecure cookies.

## API Client Operations

Create scoped machine credentials in `/admin/api-clients`. The `client_secret` is displayed only when the client is created or rotated; store it in the integration secret manager immediately.

Use HTTP Basic auth:

```bash
curl -u "$CLIENT_ID:$CLIENT_SECRET" http://localhost:8080/api/v1/secret-links
```

Rotate client secrets regularly, set expirations for automation clients, and disable or revoke unused clients. In production, Basic auth requires HTTPS through the public endpoint or trusted reverse proxy.

## Health Checks

- `/health/live`: process is alive.
- `/health/ready`: PostgreSQL ping succeeds, Vault is initialized and unsealed, and the Transit key exists.

Compose health checks use these endpoints.

## Metrics

Prometheus metrics are exposed at `/metrics`:

- `secureshare_secret_created_total`
- `secureshare_secret_consumed_total`
- `secureshare_secret_unavailable_total`
- `secureshare_secret_revoked_total`
- `secureshare_secret_expired_total`
- `secureshare_login_failures_total`
- `secureshare_csrf_failures_total`
- `secureshare_rate_limit_events_total`
- `secureshare_vault_errors_total`
- `secureshare_vault_latency_seconds`
- `secureshare_database_latency_seconds`
- `secureshare_consume_duration_seconds`
- `secureshare_cleanup_duration_seconds`
- `secureshare_cleanup_deletions_total`
- `secureshare_stale_lease_recovery_total`
- `secureshare_active_secrets`

Metrics avoid token IDs, merchant IDs, usernames, recipient references, and other high-cardinality labels.

## API Documentation

The local Swagger UI is served from bundled assets at `/docs`. The raw OpenAPI 3.1 spec is served at `/openapi.yaml`. Both require a logged-in user with API documentation permission unless `OPENAPI_PUBLIC=true`.

Run local validation before deployment:

```bash
make openapi-validate
```

To run local Prometheus:

```bash
docker compose --profile observability up -d prometheus
```

## Logging

Logs are JSON through `slog`. They include request ID, method, path, status, latency, and keyed IP hash. They do not include request bodies, response bodies, raw tokens, passwords, API keys, Authorization headers, or full secret URLs.

Ship logs to a protected sink in production and configure redaction in every proxy, WAF, APM, and trace collector.

## PostgreSQL Operations

Use persistent volumes locally. In production:

- Enable TLS.
- Use least-privilege credentials.
- Encrypt storage.
- Back up regularly.
- Test restore regularly.
- Monitor locks, connections, replication lag, and disk usage.

Migrations run automatically at app startup from the `migrations` directory.

## Vault Production Migration

Local Compose uses Vault dev mode only. Production must use:

- Persistent Vault storage
- Initialized and unsealed cluster
- Transit enabled
- `secureshare` key created
- AppRole, Kubernetes Auth, or equivalent
- Short-lived tokens
- Token renewal and expiry monitoring
- Audit devices
- HA storage and documented unseal approach
- Transit key rotation
- Backup and restore procedures

Use `deploy/vault/secureshare-policy.hcl` as the minimum app policy.

## Reverse Proxy Configuration

Required:

- HTTPS termination
- HSTS
- Request body logging disabled for sensitive endpoints
- Response body logging disabled for reveal responses
- URI and header redaction
- Reasonable request size limits
- Trusted `X-Forwarded-For` handling

See `deploy/nginx/secureshare.conf` for a concrete NGINX example with token-safe URI logging and no request-body logging.

Example headers:

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Forwarded-Proto: https
```

## TLS and HSTS

Production must be HTTPS-only. Set `APP_ENV=production` to emit HSTS from the app as an additional guard, but prefer enforcing HSTS at the public reverse proxy too.

## Production Compose

Local development uses `docker-compose.yml`. Production examples use:

```bash
docker compose --env-file /etc/secureshare/secureshare.env -f docker-compose.production.yml up -d --build
```

The production Compose file expects external PostgreSQL and Vault, binds the app to loopback by default, enables secure cookies, uses production mode, drops Linux capabilities, applies no-new-privileges, uses a read-only root filesystem, and caps container logs. Do not commit the production environment file.

## Scaling

For multiple app replicas:

- Use shared session storage.
- Replace the in-memory limiter with Redis or another shared limiter.
- Keep PostgreSQL as the one-time consumption authority.
- Run one or more cleanup workers; cleanup queries are idempotent.

## Cleanup Behavior

The cleanup worker:

- Marks expired active records.
- Clears stale consuming leases.
- Blanks ciphertext for consumed, expired, and revoked records after retention.
- Deletes audit events after configured retention.

Consumed payload retention defaults to zero, so ciphertext is blanked during successful consume.

## Troubleshooting

- App exits on startup: check required environment variables and migrations.
- Readiness fails with Vault unavailable: check `vault-bootstrap` logs and the Transit key.
- Readiness fails with PostgreSQL unavailable: check `pg_isready`, credentials, and volume state.
- API returns 401: confirm API client status, expiration, scopes, and Basic auth credentials. For legacy automation, confirm `SECURESHARE_ADMIN_API_KEY` and `LEGACY_ADMIN_API_KEY_ENABLED=true`.
- Recipient receives 410: state is intentionally not disclosed.
- Recipient receives 503: Vault decrypt failed and the secret was restored to active.

## Upgrade Process

1. Review migrations.
2. Back up PostgreSQL.
3. Confirm Vault health and audit logging.
4. Deploy the new image.
5. Verify `/health/ready`.
6. Run the smoke test.
7. Run the security test.
8. Watch metrics and logs for Vault errors, unavailable spikes, login failures, CSRF failures, cleanup duration, and latency.
