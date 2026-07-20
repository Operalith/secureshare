# API

Base URL for local development:

```text
http://localhost:8080
```

All responses use JSON for API endpoints.

## Authentication

Internal management endpoints accept:

```http
Authorization: Bearer <admin-api-key>
```

The web UI login uses the same key and stores only an opaque HTTP-only SameSite session cookie.

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
  --data '{"api_key":"change-me"}'
```

Form login is used by `/login`.

## POST /api/v1/auth/logout

Clears the server-side session cookie.

## POST /api/v1/secret-links

Requires `secret:create`.

```bash
curl -sS -X POST http://localhost:8080/api/v1/secret-links \
  -H 'Authorization: Bearer change-me' \
  -H 'Content-Type: application/json' \
  --data '{
    "title": "Merchant production credentials",
    "description": "Initial access credentials",
    "recipient_reference": "merchant-1001",
    "secret": {
      "username": "merchant-1001",
      "password": "temporary-password",
      "api_key": "example-api-key"
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

## GET /api/v1/secret-links/{id}

Requires `secret:read-metadata`.

Returns only non-sensitive metadata:

```bash
curl -sS http://localhost:8080/api/v1/secret-links/<id> \
  -H 'Authorization: Bearer change-me'
```

## POST /api/v1/secret-links/{id}/revoke

Requires `secret:revoke`.

```bash
curl -sS -X POST http://localhost:8080/api/v1/secret-links/<id>/revoke \
  -H 'Authorization: Bearer change-me'
```

Revocation blanks ciphertext immediately.

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
  "password_required": false
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
  "secret": {
    "username": "merchant-1001",
    "password": "temporary-password",
    "api_key": "example-api-key"
  }
}
```

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
