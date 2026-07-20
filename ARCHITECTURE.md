# Architecture

## Components

```mermaid
flowchart TB
  subgraph Browser
    A["Admin pages"]
    R["Recipient /s page"]
  end
  subgraph App["Go SecureShare app"]
    H["HTTP handlers and templates"]
    S["Delivery service"]
    L["In-memory rate limiter"]
    C["Cleanup worker"]
    M["Prometheus metrics"]
    AU["Safe audit events"]
  end
  DB[("PostgreSQL")]
  V["Vault Transit"]

  A --> H
  R --> H
  H --> L
  H --> S
  S --> DB
  S --> V
  S --> AU
  AU --> DB
  C --> DB
  C --> M
  S --> M
```

## Create Flow

```mermaid
sequenceDiagram
  participant Admin
  participant App
  participant Vault
  participant DB
  Admin->>App: POST /api/v1/secret-links
  App->>App: validate auth, TTL, payload size
  App->>App: generate random token
  App->>App: derive token HMAC
  App->>Vault: encrypt plaintext with Transit
  Vault-->>App: vault ciphertext
  App->>DB: insert metadata, token_hash, ciphertext
  App-->>Admin: URL with token in fragment
```

The creation response never returns the plaintext secret.

## Reveal Flow

```mermaid
sequenceDiagram
  participant Browser
  participant App
  participant DB
  participant Vault
  Browser->>Browser: read #token and remove fragment
  Browser->>App: POST /prepare with token
  App->>DB: check active and non-expired
  App-->>Browser: may_attempt
  Browser->>App: POST /consume after Reveal click
  App->>DB: active to consuming with lease
  App->>Vault: decrypt ciphertext
  Vault-->>App: plaintext
  App->>DB: consuming to consumed, blank ciphertext
  App-->>Browser: plaintext once
```

## Atomic State Machine

```mermaid
stateDiagram-v2
  [*] --> active
  active --> consuming: reveal starts
  consuming --> consumed: decrypt delivered
  consuming --> active: Vault failure or stale lease cleanup
  active --> expired: TTL elapsed
  active --> revoked: admin revoke
  consuming --> revoked: admin revoke
  consumed --> [*]
  expired --> [*]
  revoked --> [*]
```

Only the holder of `consuming_lease_id` can restore or complete a consuming row.

## Database Model

The `secret_deliveries` table stores:

- UUID delivery ID
- Unique 32-byte token HMAC
- Vault ciphertext
- Safe metadata
- Status timestamps
- Optional Argon2id password hash
- Failed attempt counters

It does not store raw tokens or plaintext secrets.

The `audit_events` table stores safe operational events only:

- Event type and result
- Optional delivery ID
- Actor ID
- Hashed IP
- Request ID
- Timestamp

It does not store payloads, raw tokens, full URLs, passwords, API keys, Authorization headers, Vault ciphertext, or user-agent strings.

## Failure Scenarios

- Vault encrypt failure during create: no database row is created.
- Vault decrypt failure during consume: leased row is restored to `active`; the recipient receives `503`.
- Duplicate consume: only one request can transition to `consuming`; others receive generic unavailable responses.
- Expired token: cleanup marks it `expired`; API still returns generic unavailable.
- Revoked token: payload is blanked and reveal returns generic unavailable.

## Cleanup Lifecycle

The cleanup worker:

- Marks active expired rows as `expired`.
- Restores stale consuming leases.
- Blanks consumed, expired, and revoked payloads after configured retention.
- Deletes audit events after configured retention.
- Updates active secret, cleanup duration, cleanup deletion, and stale lease recovery metrics.

## Observability Model

Metrics intentionally avoid delivery IDs, recipient references, titles, usernames, token hashes, or other high-cardinality labels. Fixed labels are used only for operation classes such as Vault operation, database operation, rate limit area, and cleanup deletion kind.

## Scaling Considerations

The MVP app is stateless except for in-memory sessions and rate limits. For multiple replicas, add:

- Shared session storage
- Redis-backed rate limiting
- A trusted reverse proxy that sets client IP headers
- Centralized logs and metrics
- A production Vault auth method

PostgreSQL remains the one-time guarantee authority.

## Production Boundaries

Local Docker Compose includes PostgreSQL and Vault dev mode for development. Production should use `docker-compose.production.yml` or equivalent platform manifests with external PostgreSQL and production Vault. The app expects HTTPS termination and sensitive log redaction at the reverse proxy; `deploy/nginx/secureshare.conf` is an example.
