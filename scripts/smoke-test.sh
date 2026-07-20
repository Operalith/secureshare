#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "${ROOT_DIR}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/.env"
  set +a
fi

BASE_URL="${APP_BASE_URL:-http://localhost:8080}"
ADMIN_KEY="${SECURESHARE_ADMIN_API_KEY:-change-me}"

json_get() {
  python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1"
}

wait_ready() {
  for _ in $(seq 1 90); do
    if curl -fsS "${BASE_URL}/health/ready" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "SecureShare did not become ready" >&2
  return 1
}

request_with_status() {
  local body_file status_file
  body_file="$(mktemp)"
  status_file="$(mktemp)"
  curl -sS -o "${body_file}" -w "%{http_code}" "$@" >"${status_file}"
  cat "${body_file}"
  printf '\n__STATUS__%s\n' "$(cat "${status_file}")"
  rm -f "${body_file}" "${status_file}"
}

status_of() {
  awk -F'__STATUS__' '/__STATUS__/ {print $2}' <<<"$1"
}

body_of() {
  sed '/^__STATUS__/d' <<<"$1"
}

wait_ready

create_payload='{"title":"Smoke test","description":"Automated smoke test","recipient_reference":"local-smoke","secret":{"smoke":"secureshare-ok"},"expires_in_seconds":900,"password":null,"max_failed_attempts":5}'
create_result="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links" \
  -H "Authorization: Bearer ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  --data "${create_payload}")"
create_status="$(status_of "${create_result}")"
if [[ "${create_status}" != "201" ]]; then
  echo "Create failed with HTTP ${create_status}" >&2
  body_of "${create_result}" >&2
  exit 1
fi

create_body="$(body_of "${create_result}")"
url="$(json_get url <<<"${create_body}")"
token="${url##*#}"
if [[ -z "${token}" || "${token}" == "${url}" ]]; then
  echo "Create response did not contain a URL fragment token" >&2
  exit 1
fi

prepare_result="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links/prepare" \
  -H "Content-Type: application/json" \
  --data "{\"token\":\"${token}\"}")"
if [[ "$(status_of "${prepare_result}")" != "200" ]]; then
  echo "Prepare failed" >&2
  exit 1
fi

consume_result="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links/consume" \
  -H "Content-Type: application/json" \
  --data "{\"token\":\"${token}\"}")"
if [[ "$(status_of "${consume_result}")" != "200" ]]; then
  echo "First consume failed" >&2
  body_of "${consume_result}" >&2
  exit 1
fi
if [[ "$(body_of "${consume_result}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["secret"]["smoke"])')" != "secureshare-ok" ]]; then
  echo "Consumed secret did not match expected value" >&2
  exit 1
fi

second_result="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links/consume" \
  -H "Content-Type: application/json" \
  --data "{\"token\":\"${token}\"}")"
if [[ "$(status_of "${second_result}")" != "410" ]]; then
  echo "Second consume did not return 410 Gone" >&2
  body_of "${second_result}" >&2
  exit 1
fi

echo "Smoke test passed."
