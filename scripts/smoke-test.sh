#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "${ROOT_DIR}/.env" && "${SECURESHARE_SKIP_ENV_FILE:-}" != "1" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/.env"
  set +a
fi

BASE_URL="${APP_BASE_URL:-http://localhost:8080}"
ADMIN_USERNAME="${BOOTSTRAP_ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${BOOTSTRAP_ADMIN_PASSWORD:-change-me-now}"
CANARY="${SECURESHARE_TEST_RUN_ID:-smoke-canary-$(date +%s)-$$}"
SMOKE_USERNAME="smoke-user-${CANARY}"
SMOKE_PASSWORD="smoke-password-${CANARY}"
SMOKE_API_KEY="smoke-api-key-${CANARY}"
TEST_SMTP_ENABLED="${TEST_SMTP_ENABLED:-false}"
MAILPIT_API_URL="${MAILPIT_API_URL:-}"
TEST_SMTP_HOST="${TEST_SMTP_HOST:-mailpit}"
TEST_SMTP_PORT="${TEST_SMTP_PORT:-1025}"

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

json_expect_true() {
  python3 -c 'import json,sys; data=json.load(sys.stdin); sys.exit(0 if data.get(sys.argv[1]) is True else 1)' "$1"
}

mailpit_clear() {
  if [[ -z "${MAILPIT_API_URL}" ]]; then
    return 0
  fi
  curl -fsS -X DELETE "${MAILPIT_API_URL}/api/v1/messages" >/dev/null 2>&1 || true
}

mailpit_assert_message() {
  local subject="$1"
  local expected_text="$2"
  shift 2
  python3 - "${MAILPIT_API_URL}" "${subject}" "${expected_text}" "$@" <<'PY'
import json
import sys
import time
import urllib.parse
import urllib.request

api, subject, expected, *forbidden = sys.argv[1:]

def fetch(path):
    with urllib.request.urlopen(api.rstrip("/") + path, timeout=5) as response:
        return response.read().decode("utf-8", errors="replace")

deadline = time.time() + 30
last = ""
while time.time() < deadline:
    try:
        listing_raw = fetch("/api/v1/messages")
        listing = json.loads(listing_raw)
        messages = listing.get("messages") or listing.get("Messages") or []
        for message in messages:
            message_subject = message.get("Subject") or message.get("subject") or ""
            if subject not in message_subject:
                continue
            message_id = message.get("ID") or message.get("Id") or message.get("id")
            detail = listing_raw
            if message_id:
                try:
                    detail = fetch("/api/v1/message/" + urllib.parse.quote(str(message_id), safe=""))
                except Exception:
                    detail = json.dumps(message)
                try:
                    detail += "\n" + fetch("/api/v1/message/" + urllib.parse.quote(str(message_id), safe="") + "/raw")
                except Exception:
                    pass
            combined = listing_raw + "\n" + detail
            if expected not in combined:
                raise SystemExit("captured email did not contain expected message text")
            if "http://localhost:18080/s#" not in combined and "http://localhost:8080/s#" not in combined:
                raise SystemExit("captured email did not contain a fragment secure link")
            lowered = combined.lower()
            if ("text/plain" not in lowered and '"text"' not in lowered) or ("text/html" not in lowered and '"html"' not in lowered):
                raise SystemExit("captured email did not expose both text and HTML content")
            for value in forbidden:
                if value and value in combined:
                    raise SystemExit("captured email leaked forbidden value")
            sys.exit(0)
        last = listing_raw
    except Exception as exc:
        last = str(exc)
    time.sleep(1)
raise SystemExit("expected email was not captured by Mailpit: " + last[:500])
PY
}

compose_logs() {
  if [[ -z "${COMPOSE_PROJECT_NAME:-}" ]]; then
    docker compose -f "${ROOT_DIR}/docker-compose.yml" logs --no-color "${SECURESHARE_APP_SERVICE:-app}" 2>/dev/null || true
    return 0
  fi
  docker compose -f "${ROOT_DIR}/docker-compose.yml" -p "${COMPOSE_PROJECT_NAME}" logs --no-color "${SECURESHARE_APP_SERVICE:-app}" 2>/dev/null || true
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

if [[ "${TEST_SMTP_ENABLED}" == "true" ]]; then
  mailpit_clear
  smtp_payload="$(python3 - "${TEST_SMTP_HOST}" "${TEST_SMTP_PORT}" <<'PY'
import json
import sys

host, port = sys.argv[1], int(sys.argv[2])
print(json.dumps({
    "enabled": True,
    "smtp_host": host,
    "smtp_port": port,
    "encryption_mode": "none",
    "smtp_username": "",
    "smtp_password": "",
    "from_name": "SecureShare Tests",
    "from_email": "secureshare-tests@example.local",
    "reply_to_email": "support@example.local",
    "connection_timeout_seconds": 5,
    "send_timeout_seconds": 10,
    "default_subject": "SecureShare default test message",
    "default_message": "Hello {{recipient_name}},\n\nUse {{secure_link}} to open the test secret.\n\nRegards,\n{{sender_name}}",
    "footer_text": "Development-only captured email",
}))
PY
)"
  smtp_save="$(request_with_status -b "${cookie_jar}" -X PUT "${BASE_URL}/api/v1/settings/email" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: ${csrf_token}" \
    --data "${smtp_payload}")"
  assert_status "$(status_of "${smtp_save}")" "200" "SMTP settings save"

  smtp_test="$(request_with_status -b "${cookie_jar}" -X POST "${BASE_URL}/api/v1/settings/email/test-connection" \
    -H "X-CSRF-Token: ${csrf_token}")"
  assert_status "$(status_of "${smtp_test}")" "200" "SMTP connection test"
  body_of "${smtp_test}" | json_expect_true ok

  send_test="$(request_with_status -b "${cookie_jar}" -X POST "${BASE_URL}/api/v1/settings/email/send-test" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: ${csrf_token}" \
    --data '{"to":"smoke-recipient@example.local"}')"
  assert_status "$(status_of "${send_test}")" "200" "SMTP test delivery"
  body_of "${send_test}" | json_expect_true ok
fi

api_client_payload='{"name":"Smoke test client","scopes":["secret:create","secret:read-metadata","secret:revoke","email:send"],"expires_at":""}'
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
payload = {
    "title": "Smoke mixed credential",
    "description": "Automated smoke test",
    "recipient_reference": password.removeprefix("smoke-password-"),
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
}
if __import__("os").environ.get("TEST_SMTP_ENABLED") == "true":
    payload["delivery"] = {
        "email": {
            "send": True,
            "to": "smoke-recipient@example.local",
            "recipient_name": "Smoke Recipient",
            "use_default_template": False,
            "subject": "Smoke secure package",
            "message": "Hello {{recipient_name}},\n\nSmoke custom delivery message.\n\n{{secure_link}}\n\nExpires at {{expires_at}}.",
        }
    }
print(json.dumps(payload))
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

if [[ "${TEST_SMTP_ENABLED}" == "true" ]]; then
  CREATE_BODY="${create_body}" python3 - <<'PY'
import json
import os
import sys

body = json.loads(os.environ["CREATE_BODY"])
email = body.get("delivery", {}).get("email", {})
if email.get("status") != "sent" or email.get("requested") is not True:
    raise SystemExit(f"email delivery was not sent: {email!r}")
if email.get("to") != "s***@example.local":
    raise SystemExit(f"recipient was not masked as expected: {email!r}")
PY
  mailpit_assert_message "Smoke secure package" "Smoke custom delivery message" "${SMOKE_USERNAME}" "${SMOKE_PASSWORD}" "${SMOKE_API_KEY}"
fi

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

logs="$(compose_logs)"
for leaked in "${SMOKE_USERNAME}" "${SMOKE_PASSWORD}" "${SMOKE_API_KEY}" "${token}" "${client_secret}"; do
  if [[ -n "${leaked}" ]] && grep -F "${leaked}" <<<"${logs}" >/dev/null; then
    echo "sensitive smoke value appeared in app logs" >&2
    exit 1
  fi
done

echo "Smoke test passed."
