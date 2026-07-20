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
ADMIN_USERNAME="${BOOTSTRAP_ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${BOOTSTRAP_ADMIN_PASSWORD:-change-me-now}"
CANARY="smoke-canary-$(date +%s)-$$"
SMOKE_USERNAME="smoke-user-${CANARY}"
SMOKE_PASSWORD="smoke-password-${CANARY}"
SMOKE_API_KEY="smoke-api-key-${CANARY}"

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

json_get() {
  python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1"
}

assert_status() {
  local actual="$1"
  local expected="$2"
  local label="$3"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "${label}: got HTTP ${actual}, want ${expected}" >&2
    exit 1
  fi
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

extract_token() {
  local url="$1"
  local token="${url##*#}"
  if [[ -z "${token}" || "${token}" == "${url}" ]]; then
    echo "Create response did not contain a URL fragment token" >&2
    exit 1
  fi
  printf '%s' "${token}"
}

wait_ready

cookie_jar="$(mktemp)"
login="$(request_with_status -c "${cookie_jar}" -X POST "${BASE_URL}/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  --data "{\"login\":\"${ADMIN_USERNAME}\",\"password\":\"${ADMIN_PASSWORD}\"}")"
assert_status "$(status_of "${login}")" "200" "admin login"
csrf_token="$(body_of "${login}" | json_get csrf_token)"
if [[ -z "${csrf_token}" ]]; then
  echo "Login did not return csrf_token" >&2
  exit 1
fi

api_client_payload='{"name":"Smoke test client","scopes":["secret:create","secret:read-metadata","secret:revoke"],"expires_at":""}'
api_client_result="$(request_with_status -b "${cookie_jar}" -X POST "${BASE_URL}/api/v1/api-clients" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: ${csrf_token}" \
  --data "${api_client_payload}")"
assert_status "$(status_of "${api_client_result}")" "201" "api client create"
api_client_body="$(body_of "${api_client_result}")"
client_id="$(json_get client_id <<<"${api_client_body}")"
client_secret="$(json_get client_secret <<<"${api_client_body}")"
if [[ -z "${client_id}" || -z "${client_secret}" ]]; then
  echo "API client creation did not return one-time credentials" >&2
  exit 1
fi

create_payload="$(python3 - "${SMOKE_USERNAME}" "${SMOKE_PASSWORD}" "${SMOKE_API_KEY}" <<'PY'
import json
import sys

username, password, api_key = sys.argv[1:]
print(json.dumps({
    "title": "Smoke mixed credential",
    "description": "Automated smoke test",
    "recipient_reference": "local-smoke",
    "expires_in_seconds": 900,
    "password": None,
    "max_failed_attempts": 5,
    "payload": {
        "type": "structured",
        "fields": [
            {"name": "username", "label": "Username", "value": username, "sensitive": False, "multiline": False},
            {"name": "password", "label": "Password", "value": password, "sensitive": True, "multiline": False},
            {"name": "api_key", "label": "API Key", "value": api_key, "sensitive": True, "multiline": False},
        ],
    },
}))
PY
)"
create_result="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links" \
  -u "${client_id}:${client_secret}" \
  -H "Content-Type: application/json" \
  --data "${create_payload}")"
assert_status "$(status_of "${create_result}")" "201" "mixed secret create"
create_body="$(body_of "${create_result}")"
delivery_id="$(json_get id <<<"${create_body}")"
token="$(extract_token "$(json_get url <<<"${create_body}")")"

metadata_result="$(request_with_status -X GET "${BASE_URL}/api/v1/secret-links/${delivery_id}" \
  -u "${client_id}:${client_secret}")"
assert_status "$(status_of "${metadata_result}")" "200" "metadata"
metadata_body="$(body_of "${metadata_result}")"
for leaked in "${SMOKE_USERNAME}" "${SMOKE_PASSWORD}" "${SMOKE_API_KEY}"; do
  if grep -F "${leaked}" <<<"${metadata_body}" >/dev/null; then
    echo "Metadata response leaked a secret field value" >&2
    exit 1
  fi
done

consume_result="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links/consume" \
  -H "Content-Type: application/json" \
  --data "{\"token\":\"${token}\"}")"
assert_status "$(status_of "${consume_result}")" "200" "first consume"
consume_body="$(body_of "${consume_result}")"
CONSUME_BODY="${consume_body}" python3 - "${SMOKE_USERNAME}" "${SMOKE_PASSWORD}" "${SMOKE_API_KEY}" <<'PY'
import json
import os
import sys

expected = {
    "username": sys.argv[1],
    "password": sys.argv[2],
    "api_key": sys.argv[3],
}
data = json.loads(os.environ["CONSUME_BODY"])
payload = data.get("payload", {})
fields = {field.get("name"): field.get("value") for field in payload.get("fields", [])}
if payload.get("type") != "structured" or fields != expected:
    raise SystemExit(f"unexpected consumed fields: {fields!r}")
PY

second_result="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links/consume" \
  -H "Content-Type: application/json" \
  --data "{\"token\":\"${token}\"}")"
assert_status "$(status_of "${second_result}")" "410" "second consume"

revoke_payload='{"title":"Smoke revoke target","expires_in_seconds":900,"payload":{"type":"structured","fields":[{"name":"api_key","label":"API Key","value":"example-api-key","sensitive":true,"multiline":false}]}}'
revoke_create="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links" \
  -u "${client_id}:${client_secret}" \
  -H "Content-Type: application/json" \
  --data "${revoke_payload}")"
assert_status "$(status_of "${revoke_create}")" "201" "revoke target create"
revoke_id="$(body_of "${revoke_create}" | json_get id)"
revoke_result="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links/${revoke_id}/revoke" \
  -u "${client_id}:${client_secret}")"
assert_status "$(status_of "${revoke_result}")" "200" "revoke"

docs_status="$(curl -sS -b "${cookie_jar}" -o /dev/null -w "%{http_code}" "${BASE_URL}/docs")"
assert_status "${docs_status}" "200" "Swagger UI"
openapi_status="$(curl -sS -b "${cookie_jar}" -o /tmp/secureshare-smoke-openapi.yaml -w "%{http_code}" "${BASE_URL}/openapi.yaml")"
assert_status "${openapi_status}" "200" "OpenAPI"
grep -q "openapi: 3.1.0" /tmp/secureshare-smoke-openapi.yaml

echo "Smoke test passed."
