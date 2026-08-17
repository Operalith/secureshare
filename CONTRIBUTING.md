# Contributing to SecureShare

Thank you for helping improve SecureShare. Changes that affect secret handling, authentication, authorization, cryptography, logging, email delivery, or recipient behavior require especially careful review.

## Before You Start

- Search existing issues and pull requests before opening a duplicate.
- Use GitHub Private Vulnerability Reporting for suspected vulnerabilities. Do not open a public security issue.
- Never include real credentials, raw SecureShare links, tokens, secret payloads, private domains, or production logs in an issue, commit, screenshot, or test fixture.

## Local Development

```bash
git clone https://github.com/Operalith/secureshare.git
cd secureshare
cp .env.example .env
docker compose up -d --build
curl -fsS http://localhost:8080/health/ready
```

The credentials in `.env.example` are development-only. Never reuse them outside a local disposable environment.

## Making Changes

- Keep changes focused and avoid unrelated refactors.
- Format Go code with `gofmt`.
- Use clearly fake fixtures such as `example-user`, `example-password`, and `example@example.com`.
- Preserve fragment-only tokens, one-time consumption, no-store behavior, log redaction, and backend authorization boundaries.
- Update OpenAPI, documentation, examples, and tests when behavior changes.
- Use Conventional Commits, for example `fix(reveal): preserve password retry state`.

## Tests

Run the checks relevant to your change. Before requesting release-level review, run:

```bash
go test ./...
go vet ./...
make lint
make ui-time-test
make openapi-validate
make smoke
make integration-test
make security-test
make qa-test
make ui-e2e
make recipient-qa-test
```

Docker-backed targets create isolated PostgreSQL, Vault, and Mailpit fixtures and remove them afterward. Do not commit generated reports, traces, authenticated browser state, or test artifacts.

## Pull Requests

Include:

- the problem and intended behavior;
- the security and compatibility impact;
- documentation or API changes;
- the exact validation performed;
- sanitized screenshots for visible UI changes.

Keep pull requests reviewable. Maintainers may request separate changes when a patch mixes unrelated concerns.

## Security-Sensitive Changes

Changes to token handling, encryption, consume transactions, sessions, CSRF, link passwords, SMTP credentials, API client authentication, or logging should include negative tests and a description of the relevant threat boundary.

See [SECURITY.md](SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
