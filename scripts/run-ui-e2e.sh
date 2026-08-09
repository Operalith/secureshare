#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_NAME="${SECURESHARE_UI_E2E_PROJECT:-secureshare_ui_e2e}"
RUN_ID="${SECURESHARE_TEST_RUN_ID:-ui-e2e-$(date +%Y%m%d%H%M%S)-$$}"
AUTH_DIR="$(mktemp -d -t secureshare-ui-e2e-auth)"
LOG_FILE="$(mktemp -t secureshare-ui-e2e-logs)"

export COMPOSE_PROJECT_NAME="${PROJECT_NAME}"
export SECURESHARE_TEST_ISOLATED=1
export SECURESHARE_TEST_RUN_ID="${RUN_ID}"
export TEST_APP_PORT="${TEST_APP_PORT:-18081}"
export TEST_POSTGRES_PORT="${TEST_POSTGRES_PORT:-15433}"
export TEST_VAULT_PORT="${TEST_VAULT_PORT:-18201}"
export MAILPIT_SMTP_PORT="${MAILPIT_SMTP_PORT:-11026}"
export MAILPIT_WEB_PORT="${MAILPIT_WEB_PORT:-18026}"

compose=(docker compose -f "${ROOT_DIR}/docker-compose.yml" -p "${PROJECT_NAME}" --profile test)

cleanup() {
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  if [[ -n "${AUTH_DIR}" && -d "${AUTH_DIR}" ]]; then
    rm -rf -- "${AUTH_DIR}"
  fi
  if [[ -n "${LOG_FILE}" && -f "${LOG_FILE}" ]]; then
    rm -f -- "${LOG_FILE}"
  fi
}

wait_ready() {
  for _ in $(seq 1 90); do
    if curl -fsS "http://localhost:${TEST_APP_PORT}/health/ready" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "isolated SecureShare UI stack did not become ready" >&2
  "${compose[@]}" logs --no-color app-test >&2 || true
  return 1
}

assert_dev_not_touched() {
  if ! docker compose -f "${ROOT_DIR}/docker-compose.yml" ps --status running postgres >/dev/null 2>&1; then
    return 0
  fi
  local count
  count="$(docker compose -f "${ROOT_DIR}/docker-compose.yml" exec -T postgres psql -U secureshare -d secureshare -Atc \
    "SELECT COUNT(*) FROM secret_deliveries WHERE recipient_reference = 'ui-e2e-fixture' OR title = 'Isolated QA navigation fixture';" 2>/dev/null || true)"
  if [[ -n "${count}" && "${count}" != "0" ]]; then
    echo "development database contains isolated browser test data" >&2
    return 1
  fi
}

assert_logs_redacted() {
  "${compose[@]}" logs --no-color app-test >"${LOG_FILE}" 2>/dev/null || return 1
  local label pattern
  while IFS='|' read -r label pattern; do
    if rg -q -- "${pattern}" "${LOG_FILE}"; then
      echo "isolated application logs contain forbidden ${label}" >&2
      return 1
    fi
  done <<'EOF'
raw fragment URL|/s#[A-Za-z0-9_-]{16,}
raw token field|"token"[[:space:]]*:
session cookie|ss_session=
authorization header|[Aa]uthorization:[[:space:]]
English recipient secret|english-recipient-secret-
Persian API key|QA_KEY_
recipient link password|(correct-recipient-password|english-recipient-password|persian-recipient-password|e2e-(first|replacement|remove)-link-password)
SMTP password|smtp-password-canary
API client secret|client_secret["'= :]
EOF
}

trap cleanup EXIT
mkdir -p "${ROOT_DIR}/artifacts/ui-e2e"
cleanup
"${compose[@]}" build app-test
"${compose[@]}" up -d app-test mailpit
wait_ready
set +e
(
  set -e
  cd "${ROOT_DIR}/tests/e2e"
  npm ci --ignore-scripts
  playwright_args=(test)
  if [[ "${RECIPIENT_QA_ONLY:-0}" == "1" ]]; then
    playwright_args+=(specs/recipient-retry.spec.js specs/recipient-localization.spec.js)
  fi
  BASE_URL="http://localhost:${TEST_APP_PORT}" \
  E2E_ADMIN_USERNAME="test-admin" \
  E2E_ADMIN_PASSWORD="test-admin-password-change-me" \
  E2E_BROWSER_CHANNEL="${E2E_BROWSER_CHANNEL:-chrome}" \
  PLAYWRIGHT_AUTH_DIR="${AUTH_DIR}" \
  PLAYWRIGHT_OUTPUT_DIR="${ROOT_DIR}/artifacts/ui-e2e" \
    npx playwright "${playwright_args[@]}"
)
test_status=$?
set -e
assert_dev_not_touched
log_status=0
assert_logs_redacted || log_status=$?
if [[ "${test_status}" -ne 0 ]]; then
  exit "${test_status}"
fi
exit "${log_status}"
