#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -lt 2 ]]; then
  echo "usage: $0 <label> <command> [args...]" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABEL="$1"
shift

PROJECT_NAME="${SECURESHARE_TEST_PROJECT:-secureshare_test}"
RUN_ID="${SECURESHARE_TEST_RUN_ID:-${LABEL}-test-$(date +%Y%m%d%H%M%S)-$$}"

export COMPOSE_PROJECT_NAME="${PROJECT_NAME}"
export SECURESHARE_APP_SERVICE="app-test"
export SECURESHARE_SKIP_ENV_FILE=1
export SECURESHARE_TEST_ISOLATED=1
export SECURESHARE_TEST_RUN_ID="${RUN_ID}"
export INTEGRATION_TESTS=1
export TEST_APP_PORT="${TEST_APP_PORT:-18080}"
export TEST_POSTGRES_PORT="${TEST_POSTGRES_PORT:-15432}"
export TEST_VAULT_PORT="${TEST_VAULT_PORT:-18200}"
export MAILPIT_SMTP_PORT="${MAILPIT_SMTP_PORT:-11025}"
export MAILPIT_WEB_PORT="${MAILPIT_WEB_PORT:-18025}"
export APP_BASE_URL="http://localhost:${TEST_APP_PORT}"
export SECURESHARE_ADMIN_API_KEY="${TEST_SECURESHARE_ADMIN_API_KEY:-test-admin-api-key-change-me}"
export BOOTSTRAP_ADMIN_USERNAME="test-admin"
export BOOTSTRAP_ADMIN_PASSWORD="test-admin-password-change-me"
export INTEGRATION_DATABASE_URL="postgres://secureshare:secureshare@localhost:${TEST_POSTGRES_PORT}/secureshare_test?sslmode=disable"
export TEST_SMTP_ENABLED=true
export TEST_SMTP_HOST="${TEST_SMTP_HOST:-mailpit}"
export TEST_SMTP_PORT="${TEST_SMTP_PORT:-1025}"
export MAILPIT_API_URL="http://localhost:${MAILPIT_WEB_PORT}"

compose=(docker compose -f "${ROOT_DIR}/docker-compose.yml" -p "${PROJECT_NAME}" --profile test)

cleanup() {
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}

wait_ready() {
  for _ in $(seq 1 90); do
    if curl -fsS "${APP_BASE_URL}/health/ready" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "isolated SecureShare stack did not become ready" >&2
  "${compose[@]}" logs --no-color app-test >&2 || true
  return 1
}

assert_dev_not_touched() {
  if ! docker compose -f "${ROOT_DIR}/docker-compose.yml" ps --status running postgres >/dev/null 2>&1; then
    return 0
  fi
  local count
  count="$(docker compose -f "${ROOT_DIR}/docker-compose.yml" exec -T postgres psql -U secureshare -d secureshare -Atc \
    "SELECT COUNT(*) FROM secret_deliveries WHERE recipient_reference = '${RUN_ID}' OR title LIKE '%${RUN_ID}%';" 2>/dev/null || true)"
  if [[ -n "${count}" && "${count}" != "0" ]]; then
    echo "development database contains rows for isolated test run ${RUN_ID}" >&2
    return 1
  fi
}

trap cleanup EXIT

cleanup
"${compose[@]}" up -d --build app-test mailpit
wait_ready

"$@"

assert_dev_not_touched
