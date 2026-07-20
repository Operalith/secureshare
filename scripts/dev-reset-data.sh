#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -f "${ROOT_DIR}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/.env"
  set +a
fi

if [[ "${APP_ENV:-development}" == "production" ]]; then
  echo "Refusing to reset data while APP_ENV=production." >&2
  exit 1
fi

if [[ "${SECURESHARE_CONFIRM_DEV_RESET:-}" != "reset-dev-data" ]]; then
  cat >&2 <<'EOF'
This development-only command deletes local secret deliveries, sessions, and audit events.
It preserves users, API clients, and encrypted SMTP settings.

Run again with:
  SECURESHARE_CONFIRM_DEV_RESET=reset-dev-data make dev-reset-data
EOF
  exit 2
fi

if ! docker compose -f "${ROOT_DIR}/docker-compose.yml" ps --status running postgres >/dev/null 2>&1; then
  echo "The local development PostgreSQL service is not running." >&2
  exit 1
fi

docker compose -f "${ROOT_DIR}/docker-compose.yml" exec -T postgres psql -U secureshare -d secureshare <<'SQL'
TRUNCATE TABLE sessions, audit_events, secret_deliveries RESTART IDENTITY CASCADE;
SQL

echo "Development secret deliveries, sessions, and audit events have been reset."
