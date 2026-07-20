# Developer Guide

SecureShare lets internal services create one-time links for credentials without storing plaintext payloads in PostgreSQL.

## 1. Creating an API Client

Sign in to `/login` with a local admin account and open `/admin/api-clients`. Create a client with the minimum scopes needed:

- `secret:create` for creating links
- `secret:list` or `secret:read-metadata` for listing or reading metadata
- `secret:revoke` for revocation
- `dashboard:read` for dashboard metrics

Copy the `client_id` and `client_secret` immediately. The secret is shown only once.

## 2. Authentication

Use HTTP Basic auth:

```bash
curl -u "$CLIENT_ID:$CLIENT_SECRET" http://localhost:8080/api/v1/secret-links
```

The bundled examples read `SECURESHARE_BASE_URL`, `SECURESHARE_CLIENT_ID`, and `SECURESHARE_CLIENT_SECRET`.

Use HTTPS in production. The legacy `Authorization: Bearer <admin-api-key>` mode is deprecated and can be disabled with `LEGACY_ADMIN_API_KEY_ENABLED=false`.

## 3. Creating a One-Time Secret Link

Send `POST /api/v1/secret-links` with `Content-Type: application/json`. The response contains a one-time recipient URL. Print or store only the URL needed for handoff; do not log the request body.

## 4. Supported Payload Types

`structured` payloads contain up to 50 named fields. `text` payloads preserve plain text or configuration snippets. `json` payloads preserve arbitrary JSON values.

## 5. Username and Password Example

```bash
curl -sS -X POST http://localhost:8080/api/v1/secret-links \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Merchant login",
    "expires_in_seconds": 86400,
    "payload": {
      "type": "structured",
      "fields": [
        {"name":"username","label":"Username","value":"example-user","sensitive":false,"multiline":false},
        {"name":"password","label":"Password","value":"example-password","sensitive":true,"multiline":false}
      ]
    }
  }'
```

## 6. API-Key-Only Example

```bash
curl -sS -X POST http://localhost:8080/api/v1/secret-links \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Merchant API key",
    "expires_in_seconds": 3600,
    "payload": {
      "type": "structured",
      "fields": [
        {"name":"api_key","label":"API Key","value":"example-api-key","sensitive":true,"multiline":false}
      ]
    }
  }'
```

## 7. Combined Credential Example

Use one structured payload with multiple fields:

```json
{
  "type": "structured",
  "fields": [
    {"name":"username","label":"Username","value":"example-user","sensitive":false,"multiline":false},
    {"name":"password","label":"Password","value":"example-password","sensitive":true,"multiline":false},
    {"name":"api_key","label":"API Key","value":"example-api-key","sensitive":true,"multiline":false}
  ]
}
```

## 8. Plain Text Example

```json
{
  "title": "Config snippet",
  "expires_in_seconds": 3600,
  "payload": {
    "type": "text",
    "text": "EXAMPLE_SETTING=true"
  }
}
```

## 9. JSON Example

```json
{
  "title": "JSON credentials",
  "expires_in_seconds": 3600,
  "payload": {
    "type": "json",
    "value": {
      "username": "example-user",
      "password": "example-password"
    }
  }
}
```

## 10. Expiration Behavior

Set `expires_in_seconds` for each link. Expired, consumed, revoked, unknown, locked, and invalid tokens all return the same generic unavailable response.

## 11. Password-Protected Links

Set `password` on create to require a recipient password before reveal. Link passwords are hashed with Argon2id and never returned.

## 12. Revocation

Call:

```bash
curl -sS -X POST http://localhost:8080/api/v1/secret-links/$DELIVERY_ID/revoke \
  -u "$CLIENT_ID:$CLIENT_SECRET"
```

## 13. Metadata and Listing

Metadata endpoints return titles, status, expiration, creator, and safe payload summary fields only: `payload_type`, `payload_field_count`, and `payload_contains_sensitive`.

## 14. Error Handling

Errors use:

```json
{"code":"INVALID_REQUEST","message":"Invalid request."}
```

Treat `401` as missing credentials, invalid credentials, disabled/expired clients, or missing scope. Treat `410 SECRET_UNAVAILABLE` as terminal for recipient reveal attempts.

## 15. Rate Limits

Create, prepare, consume, and login paths are rate-limited in memory. Retry `429` with backoff and jitter.

## 16. Retry Behavior

Do not blindly retry create requests if the first response status is unknown; you could create multiple valid links. Prefer application-level idempotency in the calling workflow.

## 17. Idempotency Guidance

SecureShare does not currently expose an idempotency-key API. Store your own operation ID and delivery ID mapping when integrations need exactly-once creation semantics.

## 18. Logging and Secret Redaction

Never log request bodies, response bodies from consume, raw tokens, full one-time URLs, API client secrets, Authorization headers, or recipient passwords.

## 19. Production HTTPS Requirements

Use HTTPS for all API-client requests. In production, Basic auth is accepted only when the request is HTTPS or the trusted reverse proxy sends `X-Forwarded-Proto: https`.

## 20. Example Integrations

See:

- `examples/curl/`
- `examples/go/`
- `examples/python/`
- `examples/javascript/`

The OpenAPI spec is available at `/openapi.yaml`, and the local Swagger UI is available at `/docs`.
