# Developer Guide

SecureShare lets internal services create one-time links for credentials without storing plaintext payloads in PostgreSQL.

## 1. Creating an API Client

Sign in to `/login` with a local admin account and open `/admin/api-clients`. Create a client with the minimum scopes needed:

- `secret:create` for creating links
- `secret:list` or `secret:read-metadata` for listing or reading metadata
- `secret:revoke` for revocation
- `dashboard:read` for dashboard metrics
- `email:send` for optional SMTP delivery of one-time links

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

## 10. Optional Email Delivery

SMTP is configured and enabled by an administrator at `/admin/settings/email`. Link creation without email remains the default. To send the one-time link by email, request the canonical nested model and make sure the API client has both `secret:create` and `email:send`:

```bash
curl -sS -X POST http://localhost:8080/api/v1/secret-links \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Merchant production credentials",
    "expires_in_seconds": 86400,
    "payload": {
      "type": "structured",
      "fields": [
        {"name":"username","label":"Username","value":"example-user","sensitive":false,"multiline":false},
        {"name":"password","label":"Password","value":"example-password","sensitive":true,"multiline":false},
        {"name":"api_key","label":"API Key","value":"example-api-key","sensitive":true,"multiline":false}
      ]
    },
    "delivery": {
      "email": {
        "send": true,
        "to": "merchant@example.com",
        "recipient_name": "Merchant Operations",
        "use_default_template": false,
        "subject": "{{product_name}} secure access",
        "message": "Hello {{recipient_name}},\n\nUse {{secure_link}} to open the secure package.\n\nExpires at {{expires_at}}."
      }
    }
  }'
```

Compatibility aliases are also accepted:

```json
{
  "send_email": true,
  "recipient_email": "merchant@example.com"
}
```

If both aliases and `delivery.email` are present, the nested `delivery.email` values take precedence. Unknown placeholders are rejected before the secret is created.

Supported message placeholders are `{{secure_link}}`, `{{secret_title}}`, `{{recipient_name}}`, `{{recipient_email}}`, `{{sender_name}}`, `{{expires_at}}`, `{{expires_in}}`, `{{product_name}}`, and `{{support_email}}`. Subjects allow only `{{secret_title}}`, `{{product_name}}`, and `{{sender_name}}`. Messages are plain text; SecureShare escapes HTML and generates `text/plain` plus `text/html` email parts. The secret payload, link password, SMTP credentials, token hash, and Vault ciphertext are never emailed.

If SMTP is disabled or deterministically invalid, create returns `422 EMAIL_DELIVERY_NOT_CONFIGURED` and no secret is created. If the secret is created and SMTP later fails at runtime, the response is still `201 Created` with the one-time URL and `delivery.email.status="failed"` so the creator can copy the link manually.

Historical resend is unavailable because raw tokens and full URLs are not stored. The immediate creation page can retry by POSTing the raw token held in memory to `/api/v1/secret-links/send-email`; after refresh or navigation, create a new link or deliver the copied URL manually.

Do not log email request bodies, rendered email bodies, raw tokens, full URLs, recipient email addresses, SMTP errors, or API client secrets. Use caller-side idempotency when retrying create requests so a network timeout does not create multiple valid links.

Production SMTP must use TLS or STARTTLS with certificate validation. The development-only `none` mode is rejected when `APP_ENV=production`.

## 11. Expiration Behavior

Set `expires_in_seconds` for each link. Expired, consumed, revoked, unknown, locked, and invalid tokens all return the same generic unavailable response.

## 12. Password-Protected Links

Set `password` on create to require a recipient password before reveal. Link passwords are hashed with Argon2id and never returned.

## 13. Revocation

Call:

```bash
curl -sS -X POST http://localhost:8080/api/v1/secret-links/$DELIVERY_ID/revoke \
  -u "$CLIENT_ID:$CLIENT_SECRET"
```

## 14. Metadata and Listing

Metadata endpoints return titles, status, expiration, creator, and safe payload summary fields only: `payload_type`, `payload_field_count`, and `payload_contains_sensitive`.

## 15. Error Handling

Errors use:

```json
{"code":"INVALID_REQUEST","message":"Invalid request."}
```

Treat `401` as missing credentials, invalid credentials, disabled/expired clients, or missing scope. Treat `410 SECRET_UNAVAILABLE` as terminal for recipient reveal attempts. Treat `422 EMAIL_DELIVERY_NOT_CONFIGURED` as an administrator action item, not a retriable create failure.

## 16. Rate Limits

Create, prepare, consume, login, SMTP test email, email delivery, and immediate email retry paths are rate-limited in memory. Retry `429` with backoff and jitter. Multi-instance deployments need a shared limiter.

## 17. Retry Behavior

Do not blindly retry create requests if the first response status is unknown; you could create multiple valid links. Prefer application-level idempotency in the calling workflow.

## 18. Idempotency Guidance

SecureShare does not currently expose an idempotency-key API. Store your own operation ID and delivery ID mapping when integrations need exactly-once creation semantics.

## 19. Logging and Secret Redaction

Never log request bodies, response bodies from consume, raw tokens, full one-time URLs, rendered email bodies, recipient emails, API client secrets, Authorization headers, SMTP credentials, or recipient passwords.

## 20. Production HTTPS Requirements

Use HTTPS for all API-client requests. In production, Basic auth is accepted only when the request is HTTPS or the trusted reverse proxy sends `X-Forwarded-Proto: https`.

## 21. Example Integrations

See:

- `examples/curl/`
- `examples/go/`
- `examples/python/`
- `examples/javascript/`

The OpenAPI spec is available at `/openapi.yaml`, and the local Swagger UI is available at `/docs`.
