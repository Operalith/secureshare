# API

Base URL for local development:

```text
http://localhost:8080
```

All responses use JSON for API endpoints.

## Authentication

Machine integrations should authenticate with scoped API clients over HTTP Basic auth:

```http
Authorization: Basic base64(client_id:client_secret)
```

With curl:

```bash
curl -u "$CLIENT_ID:$CLIENT_SECRET" ...
```

API client secrets are shown only at creation or rotation time. The server stores only an HMAC of the client secret with `TOKEN_HMAC_PEPPER`. Basic auth must be used only over HTTPS outside local development.

Internal management endpoints still accept the deprecated legacy admin key for machine-to-machine compatibility when `LEGACY_ADMIN_API_KEY_ENABLED=true`:

```http
Authorization: Bearer <admin-api-key>
```

The web UI uses PostgreSQL-backed users and stores only an opaque HTTP-only SameSite session cookie. New integrations should use API clients instead of the legacy global key.
Browser session requests that change state must include the CSRF token from the page meta tag as `X-CSRF-Token` or form field `csrf_token`. Machine-authenticated Basic and legacy bearer requests are exempt from browser CSRF protection.

JSON endpoints require:

```http
Content-Type: application/json
```

## Error Model

```json
{
  "code": "SECRET_UNAVAILABLE",
  "message": "This secret has expired, was revoked, or has already been viewed."
}
```

Stable codes:

- `INVALID_REQUEST`
- `UNAUTHORIZED`
- `FORBIDDEN`
- `SECRET_UNAVAILABLE`
- `RATE_LIMITED`
- `PAYLOAD_TOO_LARGE`
- `INTERNAL_ERROR`
- `DEPENDENCY_UNAVAILABLE`

Recipient token failures always use generic `SECRET_UNAVAILABLE`.

## POST /api/v1/auth/login

JSON:

```bash
curl -sS -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  --data '{"login":"admin","password":"change-me-now"}'
```

Form login is used by `/login`.

JSON login accepts `login` plus `password` and returns the CSRF token for browser clients:

```json
{
  "ok": true,
  "actor_id": "admin",
  "role": "admin",
  "csrf_token": "session-bound-token"
}
```

## GET /api/v1/me

Returns the current browser-authenticated user:

```json
{
  "id": "uuid",
  "username": "developer1",
  "email": "developer1@example.local",
  "role": "developer"
}
```

## POST /api/v1/auth/logout

Clears the server-side session cookie. Browser session requests require CSRF. Bearer requests return a safe success response without mutating browser cookies.

## GET /api/v1/dashboard

Requires `secret:read-metadata`.

```bash
curl -sS http://localhost:8080/api/v1/dashboard \
  -u "$CLIENT_ID:$CLIENT_SECRET"
```

Returns safe aggregate counts, recent activity, and dependency status. It does not return labels, recipient values as metrics, payloads, tokens, URLs, or ciphertext.

## GET /api/v1/secret-links

Requires `secret:read-metadata`.

Supported query parameters:

- `page`
- `page_size` of `10`, `25`, `50`, or `100`
- `status`
- `search`
- `created_from`
- `created_to`
- `expires_from`
- `expires_to`
- `sort` as `created_at` or `expires_at`
- `order` as `asc` or `desc`

```bash
curl -sS 'http://localhost:8080/api/v1/secret-links?page=1&page_size=25&status=active' \
  -u "$CLIENT_ID:$CLIENT_SECRET"
```

Response:

```json
{
  "items": [],
  "pagination": {
    "page": 1,
    "page_size": 25,
    "total_items": 0,
    "total_pages": 0
  }
}
```

List items contain safe metadata only. Historical rows cannot reconstruct one-time URLs because raw tokens are never stored.

## POST /api/v1/secret-links

Requires `secret:create`.

```bash
curl -sS -X POST http://localhost:8080/api/v1/secret-links \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H 'Content-Type: application/json' \
  --data '{
    "title": "Merchant production credentials",
    "description": "Initial access credentials",
    "recipient_reference": "merchant-1001",
    "payload": {
      "type": "structured",
      "fields": [
        {
          "name": "username",
          "label": "Username",
          "value": "example-username",
          "sensitive": false,
          "multiline": false
        },
        {
          "name": "password",
          "label": "Password",
          "value": "example-password",
          "sensitive": true,
          "multiline": false
        },
        {
          "name": "api_key",
          "label": "API Key",
          "value": "example-api-key",
          "sensitive": true,
          "multiline": false
        }
      ]
    },
    "expires_in_seconds": 86400,
    "password": null,
    "max_failed_attempts": 5
  }'
```

Response:

```json
{
  "id": "delivery-id",
  "url": "http://localhost:8080/s#secure-token",
  "status": "active",
  "expires_at": "2026-07-21T10:30:00Z"
}
```

The secret is not returned.

The legacy `secret` field is still accepted for compatibility and is converted to the canonical encrypted payload internally. New clients should use `payload`.

Supported payload types:

- `structured`: up to 50 named fields with `name`, `label`, `value`, `sensitive`, and `multiline`.
- `text`: arbitrary plain text or configuration snippets as `text`.
- `json`: JSON value as `value`.

## GET /api/v1/secret-links/{id}

Requires `secret:read-metadata`.

Returns only non-sensitive metadata:

```bash
curl -sS http://localhost:8080/api/v1/secret-links/<id> \
  -u "$CLIENT_ID:$CLIENT_SECRET"
```

## POST /api/v1/secret-links/{id}/revoke

Requires `secret:revoke`.

```bash
curl -sS -X POST http://localhost:8080/api/v1/secret-links/<id>/revoke \
  -u "$CLIENT_ID:$CLIENT_SECRET"
```

Revocation is idempotent. Revoking an active or consuming link blanks ciphertext immediately. Revoking a consumed link does not rewrite consume history.

## POST /api/v1/admin/cleanup

Requires `secret:revoke`.

```bash
curl -sS -X POST http://localhost:8080/api/v1/admin/cleanup \
  -H 'Authorization: Bearer change-me'
```

Runs the same cleanup logic as the background worker and returns counts for expired rows, payloads cleared, stale consuming leases restored, and audit rows deleted.

## API Client Administration

Admin users can manage API clients from `/admin/api-clients`.

Admin-only endpoints:

- `GET /api/v1/api-clients`
- `POST /api/v1/api-clients`
- `GET /api/v1/api-clients/{id}`
- `POST /api/v1/api-clients/{id}/disable`
- `POST /api/v1/api-clients/{id}/enable`
- `POST /api/v1/api-clients/{id}/revoke`
- `POST /api/v1/api-clients/{id}/rotate-secret`

Create request:

```json
{
  "name": "CI deployment bot",
  "scopes": ["secret:create", "secret:read-metadata"],
  "expires_at": "2026-08-20T00:00:00Z"
}
```

Create and rotate responses include `client_secret` exactly once:

```json
{
  "id": "client-id",
  "name": "CI deployment bot",
  "client_id": "ssc_example",
  "client_secret": "sscs_copy_once",
  "status": "active",
  "scopes": ["secret:create"]
}
```

List and detail responses never include `client_secret` or `client_secret_hash`.

Supported API client scopes:

- `secret:create`
- `secret:list`
- `secret:read-metadata`
- `secret:revoke`
- `dashboard:read`

Use `LEGACY_ADMIN_API_KEY_ENABLED=false` after integrations migrate to API clients.

## POST /api/v1/secret-links/prepare

No internal auth required.

```bash
curl -sS -X POST http://localhost:8080/api/v1/secret-links/prepare \
  -H 'Content-Type: application/json' \
  --data '{"token":"raw-token"}'
```

Response:

```json
{
  "may_attempt": true,
  "password_required": false,
  "expires_at": "2026-07-21T10:30:00Z"
}
```

This endpoint does not consume the secret.

## POST /api/v1/secret-links/consume

No internal auth required. The recipient must explicitly click Reveal before the browser calls this endpoint.

```bash
curl -sS -X POST http://localhost:8080/api/v1/secret-links/consume \
  -H 'Content-Type: application/json' \
  --data '{"token":"raw-token","password":"optional-password"}'
```

Success:

```json
{
  "payload": {
    "type": "structured",
    "fields": [
      {
        "name": "username",
        "label": "Username",
        "value": "example-username",
        "sensitive": false,
        "multiline": false
      }
    ]
  },
  "secret": {
    "username": "example-username"
  }
}
```

`secret` is a backward-compatible projection. New clients should read `payload`.

Unavailable:

```http
HTTP/1.1 410 Gone
```

```json
{
  "code": "SECRET_UNAVAILABLE",
  "message": "This secret has expired, was revoked, or has already been viewed."
}
```

## Health and Metrics

```bash
curl -sS http://localhost:8080/health/live
curl -sS http://localhost:8080/health/ready
curl -sS http://localhost:8080/metrics
```

Readiness checks PostgreSQL, Vault, and the configured Transit key.

## Security Notes

- Do not place raw tokens in query parameters.
- Do not log request or response bodies.
- Do not send secret links through systems that rewrite fragments into query strings.
- Use HTTPS in production.
