# Deployment

SecureShare keeps Docker Compose as the primary local deployment path and adds a production Compose example for realistic internal hosting.

## Local Development

```bash
cp .env.example .env
docker compose up -d --build
make smoke
make integration-test
make security-test
```

Local Compose starts PostgreSQL, Vault dev mode, Vault Transit bootstrap, the Go app, and optional Prometheus.

## Production Compose Example

`docker-compose.production.yml` runs only the SecureShare app and optional Prometheus. It expects production PostgreSQL and Vault to be provided externally and does not expose PostgreSQL or Vault services.

Create an environment file outside the repository:

```bash
APP_BASE_URL=https://secureshare.example.com
DATABASE_URL=postgres://secureshare_app:...@postgres.example.internal:5432/secureshare?sslmode=verify-full
VAULT_ADDR=https://vault.example.internal:8200
VAULT_TOKEN=...
VAULT_TRANSIT_KEY=secureshare
SECURESHARE_ADMIN_API_KEY=...
LEGACY_ADMIN_API_KEY_ENABLED=false
TOKEN_HMAC_PEPPER=...
SESSION_SECRET=...
CSRF_SECRET=...
REQUEST_IP_HASH_PEPPER=...
BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_EMAIL=admin@example.com
BOOTSTRAP_ADMIN_PASSWORD=...
OPENAPI_PUBLIC=false
SWAGGER_UI_ENABLED=true
```

Then start the app:

```bash
docker compose --env-file /etc/secureshare/secureshare.env -f docker-compose.production.yml up -d --build
docker compose --env-file /etc/secureshare/secureshare.env -f docker-compose.production.yml ps
curl -fsS http://127.0.0.1:8080/health/ready
```

The app port binds to `127.0.0.1` by default for a same-host reverse proxy. Use a private Docker network or private load balancer target if the reverse proxy runs elsewhere.

## Reverse Proxy

`deploy/nginx/secureshare.conf` provides an NGINX example with:

- TLS termination.
- HTTP to HTTPS redirect.
- HSTS.
- Request ID propagation.
- Rate limiting guidance.
- Sensitive route redaction in access logs.
- No request or response body logging.
- Secure headers.
- Proxy timeouts.
- `client_max_body_size 64k`.

Nginx does not receive URL fragments, but generated links, raw tokens, and secret payloads can still appear in request bodies on API routes. Do not enable `$request_body` logging, trace body capture, mirrored traffic capture, or debug body logging.

## Vault

Use `deploy/vault/secureshare-policy.hcl` for the minimum Transit policy:

```bash
vault policy write secureshare deploy/vault/secureshare-policy.hcl
```

Recommended production pattern:

- Enable Transit and create the key: `vault secrets enable transit` and `vault write -f transit/keys/secureshare`.
- Authenticate the app with AppRole, Kubernetes Auth, or another platform-native auth method.
- Issue short-lived Vault tokens and renew them through the platform or sidecar.
- Enable Vault audit devices before go-live.
- Use Vault HA storage and a documented unseal process.
- Rotate the Transit key with Vault-native rotation. Existing ciphertext remains decryptable.
- Configure Vault namespaces if the organization uses namespaces, and include the namespace in Vault client environment or proxy configuration.

Never place Vault root tokens in Compose files, `.env` files committed to Git, screenshots, tickets, or runbooks.

## PostgreSQL

Production PostgreSQL should use:

- TLS with certificate validation in `DATABASE_URL`.
- A least-privilege role that owns or can migrate only the SecureShare schema.
- Connection limits aligned with app replicas and PostgreSQL capacity.
- Storage encryption and protected backups.
- Tested restore drills.
- Statement logging that excludes parameter values for sensitive statements.
- A migration process that backs up before app startup migrations run.

The database stores Vault ciphertext, token HMACs, Argon2id password hashes, and safe metadata. It does not store raw tokens or plaintext payloads.

## API Clients

Use the bootstrap administrator to create scoped API clients at `/admin/api-clients`, then store the one-time `client_secret` in the integration secret manager. New integrations should use Basic auth with `client_id:client_secret`; disable the legacy admin bearer key with `LEGACY_ADMIN_API_KEY_ENABLED=false` after migration.

## API Documentation

Swagger UI is served from local bundled assets at `/docs`. The raw OpenAPI 3.1 spec is served at `/openapi.yaml`. Keep `OPENAPI_PUBLIC=false` unless the deployment intentionally exposes API metadata.

## Observability

Prometheus scrapes `/metrics`. Current operational metrics include:

- Secret lifecycle counters.
- Active secret gauge.
- Consume duration.
- Login failure counter.
- CSRF failure counter.
- Rate limit counter with a fixed `area` label.
- Vault latency by fixed operation label.
- Database latency by fixed operation label.
- Cleanup duration.
- Cleanup deletion counter with fixed `kind` label.
- Stale consuming lease recovery counter.

Alert on readiness failures, Vault error spikes, p95 Vault/database latency, sustained login failures, sustained CSRF failures, cleanup failures, and unexpected active secret growth.

## Upgrade

1. Review migrations and release notes.
2. Back up PostgreSQL.
3. Confirm Vault health, audit devices, and Transit key availability.
4. Deploy the new image.
5. Verify `/health/ready`.
6. Run smoke and security checks against the promoted endpoint.
7. Watch metrics and logs for at least one cleanup interval.
