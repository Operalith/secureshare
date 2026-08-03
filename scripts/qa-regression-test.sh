#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${APP_BASE_URL:-http://localhost:18080}"
ADMIN_KEY="${SECURESHARE_ADMIN_API_KEY:-test-admin-api-key-change-me}"
ADMIN_USERNAME="${BOOTSTRAP_ADMIN_USERNAME:-test-admin}"
ADMIN_PASSWORD="${BOOTSTRAP_ADMIN_PASSWORD:-test-admin-password-change-me}"
RUN_ID="${SECURESHARE_TEST_RUN_ID:-qa-test-$(date +%Y%m%d%H%M%S)-$$}"
MAILPIT_URL="${MAILPIT_API_URL:-http://localhost:18025}"
SMTP_HOST="${TEST_SMTP_HOST:-mailpit}"
SMTP_PORT="${TEST_SMTP_PORT:-1025}"

if [[ "${SECURESHARE_TEST_ISOLATED:-}" != "1" || -z "${COMPOSE_PROJECT_NAME:-}" ]]; then
  echo "QA regression tests must run through scripts/run-isolated-test.sh" >&2
  exit 2
fi
if [[ "${BASE_URL}" == "http://localhost:8080" || "${INTEGRATION_DATABASE_URL:-}" != *"secureshare_test"* ]]; then
  echo "QA regression tests refuse to target the development application or database" >&2
  exit 2
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
cookie_jar="${tmpdir}/cookies.txt"
compose=(docker compose -f "${ROOT_DIR}/docker-compose.yml" -p "${COMPOSE_PROJECT_NAME}" --profile test)

request_with_status() {
  local body_file status_file
  body_file="${tmpdir}/body-$RANDOM"
  status_file="${tmpdir}/status-$RANDOM"
  curl -sS -o "${body_file}" -w "%{http_code}" "$@" >"${status_file}"
  cat "${body_file}"
  printf '\n__STATUS__%s\n' "$(cat "${status_file}")"
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
  local actual="$1" expected="$2" label="$3"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "${label}: got HTTP ${actual}, want ${expected}" >&2
    exit 1
  fi
}

db_scalar() {
  "${compose[@]}" exec -T postgres-test psql -v ON_ERROR_STOP=1 -U secureshare -d secureshare_test -Atc "$1"
}

compose_logs() {
  "${compose[@]}" logs --no-color "${SECURESHARE_APP_SERVICE:-app-test}" 2>/dev/null || true
}

extract_token() {
  local one_time_url="$1" token="${1##*#}"
  if [[ -z "${token}" || "${token}" == "${one_time_url}" ]]; then
    echo "create response omitted the fragment token" >&2
    exit 1
  fi
  printf '%s' "${token}"
}

create_link_only() {
  local title="$1" marker="$2" result
  result="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links" \
    -H "Authorization: Bearer ${ADMIN_KEY}" \
    -H "Content-Type: application/json" \
    --data "{\"title\":\"${title}\",\"recipient_reference\":\"${RUN_ID}\",\"expires_in_seconds\":900,\"secret\":{\"value\":\"${marker}\"}}")"
  assert_status "$(status_of "${result}")" "201" "${title}"
  body_of "${result}"
}

if [[ "$(db_scalar 'SELECT COUNT(*) FROM email_settings;')" != "0" ]]; then
  echo "isolated database unexpectedly contained SMTP settings before QA" >&2
  exit 1
fi

login="$(request_with_status -c "${cookie_jar}" -X POST "${BASE_URL}/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  --data "{\"login\":\"${ADMIN_USERNAME}\",\"password\":\"${ADMIN_PASSWORD}\"}")"
assert_status "$(status_of "${login}")" "200" "browser login"
csrf_token="$(body_of "${login}" | json_get csrf_token)"
session_token="$(awk '$6 == "ss_session" {print $7}' "${cookie_jar}" | tail -1)"
if [[ -z "${csrf_token}" || -z "${session_token}" ]]; then
  echo "browser login omitted CSRF or session state" >&2
  exit 1
fi

# 1. Missing SMTP settings do not affect link-only creation.
no_smtp_marker="qa-no-smtp-secret-${RUN_ID}"
no_smtp_body="$(create_link_only "QA link without SMTP ${RUN_ID}" "${no_smtp_marker}")"
no_smtp_token="$(extract_token "$(json_get url <<<"${no_smtp_body}")")"
if [[ "$(db_scalar 'SELECT COUNT(*) FROM email_settings;')" != "0" ]]; then
  echo "link-only creation unexpectedly created SMTP settings" >&2
  exit 1
fi

# 4. A connection test without configuration returns only safe, field-specific errors.
missing_smtp_test="$(request_with_status -X POST "${BASE_URL}/api/v1/settings/email/test-connection" \
  -H "Authorization: Bearer ${ADMIN_KEY}")"
assert_status "$(status_of "${missing_smtp_test}")" "200" "missing SMTP connection test"
SMTP_ERROR_BODY="$(body_of "${missing_smtp_test}")" python3 - <<'PY'
import json
import os

data = json.loads(os.environ["SMTP_ERROR_BODY"])
fields = data.get("fields") or {}
if data.get("ok") is not False or data.get("code") != "SMTP_CONFIGURATION_ERROR":
    raise SystemExit("missing SMTP settings did not produce the stable safe category")
if data.get("message") != "SMTP configuration is incomplete.":
    raise SystemExit("missing SMTP settings did not produce the safe public message")
if "smtp_host" not in fields or "from_email" not in fields:
    raise SystemExit("missing SMTP settings did not return field-specific guidance")
if not isinstance(data.get("duration_ms"), int) or data["duration_ms"] < 0:
    raise SystemExit("SMTP configuration result omitted a safe duration")
PY

# Persist a complete but disabled configuration.
disabled_settings="$(python3 - "${SMTP_HOST}" "${SMTP_PORT}" <<'PY'
import json
import sys

host, port = sys.argv[1], int(sys.argv[2])
print(json.dumps({
    "enabled": False,
    "smtp_host": host,
    "smtp_port": port,
    "encryption_mode": "none",
    "smtp_username": "",
    "smtp_password": "",
    "from_name": "SecureShare QA",
    "from_email": "qa@example.local",
    "reply_to_email": "support@example.local",
    "connection_timeout_seconds": 5,
    "send_timeout_seconds": 10,
    "default_subject": "SecureShare QA delivery",
    "default_message": "Hello {{recipient_name}},\n\nUse {{secure_link}} to open the QA secret.",
    "footer_text": "Isolated QA",
}))
PY
)"
disabled_save="$(request_with_status -X PUT "${BASE_URL}/api/v1/settings/email" \
  -H "Authorization: Bearer ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  --data "${disabled_settings}")"
assert_status "$(status_of "${disabled_save}")" "200" "save disabled SMTP settings"

# 2. Disabled SMTP still does not affect link-only creation.
disabled_marker="qa-disabled-smtp-secret-${RUN_ID}"
disabled_body="$(create_link_only "QA link with SMTP disabled ${RUN_ID}" "${disabled_marker}")"
disabled_token="$(extract_token "$(json_get url <<<"${disabled_body}")")"

# 3. Explicit email delivery fails before inserting a secret while SMTP is disabled.
before_failed_email_count="$(db_scalar 'SELECT COUNT(*) FROM secret_deliveries;')"
failed_email_marker="qa-disabled-email-secret-${RUN_ID}"
failed_email="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links" \
  -H "Authorization: Bearer ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  --data "{\"title\":\"QA blocked email ${RUN_ID}\",\"recipient_reference\":\"${RUN_ID}\",\"expires_in_seconds\":900,\"secret\":{\"value\":\"${failed_email_marker}\"},\"delivery\":{\"email\":{\"send\":true,\"to\":\"qa-recipient@example.local\"}}}")"
assert_status "$(status_of "${failed_email}")" "422" "email create while SMTP disabled"
FAILED_EMAIL_BODY="$(body_of "${failed_email}")" python3 - <<'PY'
import json
import os
data = json.loads(os.environ["FAILED_EMAIL_BODY"])
if data.get("code") != "EMAIL_DELIVERY_NOT_CONFIGURED":
    raise SystemExit("disabled SMTP email create did not fail with the stable safe code")
PY
if [[ "$(db_scalar 'SELECT COUNT(*) FROM secret_deliveries;')" != "${before_failed_email_count}" ]]; then
  echo "disabled SMTP email failure inserted a secret delivery" >&2
  exit 1
fi

# Exercise invalid settings with a password canary and confirm the response is redacted.
smtp_password_marker="qa-smtp-password-${RUN_ID}"
invalid_settings="$(python3 - "${smtp_password_marker}" <<'PY'
import json
import sys
print(json.dumps({
    "enabled": True,
    "smtp_host": "https://invalid host",
    "smtp_port": 70000,
    "encryption_mode": "starttls",
    "smtp_username": "qa-user",
    "smtp_password": sys.argv[1],
    "from_email": "invalid-address",
    "connection_timeout_seconds": 5,
    "send_timeout_seconds": 10,
    "default_subject": "QA",
    "default_message": "Open {{secure_link}}",
}))
PY
)"
invalid_save="$(request_with_status -X PUT "${BASE_URL}/api/v1/settings/email" \
  -H "Authorization: Bearer ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  --data "${invalid_settings}")"
assert_status "$(status_of "${invalid_save}")" "400" "invalid SMTP settings"
INVALID_SMTP_BODY="$(body_of "${invalid_save}")" SMTP_PASSWORD_MARKER="${smtp_password_marker}" python3 - <<'PY'
import json
import os
raw = os.environ["INVALID_SMTP_BODY"]
data = json.loads(raw)
if data.get("code") != "SMTP_CONFIGURATION_ERROR":
    raise SystemExit("invalid SMTP settings did not return the safe configuration code")
if not {"smtp_host", "smtp_port", "from_email"}.issubset(data.get("fields") or {}):
    raise SystemExit("invalid SMTP settings did not return safe field guidance")
if os.environ["SMTP_PASSWORD_MARKER"] in raw or "https://invalid host" in raw or "invalid-address" in raw:
    raise SystemExit("invalid SMTP response leaked submitted values")
PY

# 5. Enable the isolated Mailpit configuration, test the connection, and send a test email.
enabled_settings="$(python3 - "${SMTP_HOST}" "${SMTP_PORT}" <<'PY'
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
    "from_name": "SecureShare QA",
    "from_email": "qa@example.local",
    "reply_to_email": "support@example.local",
    "connection_timeout_seconds": 5,
    "send_timeout_seconds": 10,
    "default_subject": "SecureShare QA delivery",
    "default_message": "Hello {{recipient_name}},\n\nUse {{secure_link}} to open the QA secret.",
    "footer_text": "Isolated QA",
}))
PY
)"
enabled_save="$(request_with_status -X PUT "${BASE_URL}/api/v1/settings/email" \
  -H "Authorization: Bearer ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  --data "${enabled_settings}")"
assert_status "$(status_of "${enabled_save}")" "200" "enable isolated SMTP settings"
curl -fsS -X DELETE "${MAILPIT_URL}/api/v1/messages" >/dev/null 2>&1 || true

connection_test="$(request_with_status -X POST "${BASE_URL}/api/v1/settings/email/test-connection" \
  -H "Authorization: Bearer ${ADMIN_KEY}")"
assert_status "$(status_of "${connection_test}")" "200" "Mailpit SMTP connection test"
CONNECTION_BODY="$(body_of "${connection_test}")" python3 - <<'PY'
import json
import os
data = json.loads(os.environ["CONNECTION_BODY"])
if data.get("ok") is not True or data.get("result") != "success" or data.get("duration_ms", 0) < 1:
    raise SystemExit("Mailpit connection test did not report a real successful attempt")
PY

test_recipient="qa-test-recipient@example.local"
send_test="$(request_with_status -X POST "${BASE_URL}/api/v1/settings/email/send-test" \
  -H "Authorization: Bearer ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  --data "{\"to\":\"${test_recipient}\"}")"
assert_status "$(status_of "${send_test}")" "200" "Mailpit SMTP test email"
SEND_TEST_BODY="$(body_of "${send_test}")" python3 - <<'PY'
import json
import os
data = json.loads(os.environ["SEND_TEST_BODY"])
if data.get("ok") is not True or data.get("result") != "success" or data.get("duration_ms", 0) < 1:
    raise SystemExit("Mailpit test email did not report a real successful send")
PY
python3 - "${MAILPIT_URL}" "${test_recipient}" <<'PY'
import json
import sys
import time
import urllib.request

api, recipient = sys.argv[1:]
deadline = time.time() + 20
while time.time() < deadline:
    with urllib.request.urlopen(api.rstrip("/") + "/api/v1/messages", timeout=5) as response:
        data = json.load(response)
    for message in data.get("messages", []):
        subject = message.get("Subject") or message.get("subject") or ""
        recipients = json.dumps(message)
        if "SecureShare SMTP test" in subject and recipient in recipients:
            raise SystemExit(0)
    time.sleep(0.5)
raise SystemExit("Mailpit did not capture the SecureShare SMTP test email")
PY

# 6. API timestamp values stay normalized to UTC.
api_client_create="$(request_with_status -X POST "${BASE_URL}/api/v1/api-clients" \
  -H "Authorization: Bearer ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  --data "{\"name\":\"QA timestamp isolation ${RUN_ID}\",\"scopes\":[\"secret:create\"],\"expires_at\":\"2031-08-03T12:00:00+03:30\"}")"
assert_status "$(status_of "${api_client_create}")" "201" "QA API client create"
api_client_body="$(body_of "${api_client_create}")"
api_client_uuid="$(json_get id <<<"${api_client_body}")"
api_client_secret="$(json_get client_secret <<<"${api_client_body}")"
if [[ ! "${api_client_uuid}" =~ ^[0-9a-f-]{36}$ || -z "${api_client_secret}" ]]; then
  echo "API client creation omitted its identifier or one-time secret" >&2
  exit 1
fi
API_CLIENT_BODY="${api_client_body}" python3 - <<'PY'
import json
import os
data = json.loads(os.environ["API_CLIENT_BODY"])
if data.get("expires_at") != "2031-08-03T08:30:00Z":
    raise SystemExit("API client expiration was not normalized to UTC")
PY

api_client_detail="$(request_with_status -X GET "${BASE_URL}/api/v1/api-clients/${api_client_uuid}" \
  -H "Authorization: Bearer ${ADMIN_KEY}")"
assert_status "$(status_of "${api_client_detail}")" "200" "QA API client detail"
API_CLIENT_DETAIL="$(body_of "${api_client_detail}")" API_CLIENT_SECRET="${api_client_secret}" python3 - <<'PY'
import json
import os
raw = os.environ["API_CLIENT_DETAIL"]
data = json.loads(raw)
if data.get("expires_at") != "2031-08-03T08:30:00Z":
    raise SystemExit("API detail expiration was not UTC")
if os.environ["API_CLIENT_SECRET"] in raw or "client_secret" in data or "client_secret_hash" in raw:
    raise SystemExit("API client detail recovered one-time secret material")
PY

# 7. Admin markup preserves UTC and delegates display to the shared browser-local formatter.
client_page="$(request_with_status -b "${cookie_jar}" -X GET "${BASE_URL}/admin/api-clients/${api_client_uuid}")"
assert_status "$(status_of "${client_page}")" "200" "QA API client browser page"
client_page_body="$(body_of "${client_page}")"
if ! grep -F 'data-local-time="2031-08-03T08:30:00Z"' <<<"${client_page_body}" >/dev/null || \
   ! grep -F 'title="2031-08-03T08:30:00Z"' <<<"${client_page_body}" >/dev/null || \
   ! grep -F '/static/time.js' <<<"${client_page_body}" >/dev/null; then
  echo "API client UI did not preserve browser-local formatting hooks" >&2
  exit 1
fi
TZ=Asia/Tehran node "${ROOT_DIR}/scripts/time-formatter-test.js" >/dev/null

# 8. Delivered OAuth fields neither create nor mutate the existing API client.
before_client_count="$(db_scalar 'SELECT COUNT(*) FROM api_clients;')"
before_client_row="$(db_scalar "SELECT md5(row_to_json(api_clients)::text) FROM api_clients WHERE id = '${api_client_uuid}';")"
payload_client_id="qa-oauth-client-id-${RUN_ID}"
payload_client_secret="qa-oauth-client-secret-${RUN_ID}"
payload_create="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links" \
  -H "Authorization: Bearer ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  --data "{\"title\":\"QA delivered OAuth fields ${RUN_ID}\",\"recipient_reference\":\"${RUN_ID}\",\"expires_in_seconds\":900,\"payload\":{\"type\":\"structured\",\"fields\":[{\"name\":\"client_id\",\"label\":\"OAuth Client ID\",\"value\":\"${payload_client_id}\",\"sensitive\":false,\"multiline\":false},{\"name\":\"client_secret\",\"label\":\"OAuth Client Secret\",\"value\":\"${payload_client_secret}\",\"sensitive\":true,\"multiline\":false}]}}")"
assert_status "$(status_of "${payload_create}")" "201" "OAuth credential payload create"
payload_token="$(extract_token "$(body_of "${payload_create}" | json_get url)")"
payload_consume="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links/consume" \
  -H "Content-Type: application/json" \
  --data "{\"token\":\"${payload_token}\"}")"
assert_status "$(status_of "${payload_consume}")" "200" "OAuth credential payload consume"
PAYLOAD_BODY="$(body_of "${payload_consume}")" EXPECTED_CLIENT_ID="${payload_client_id}" EXPECTED_CLIENT_SECRET="${payload_client_secret}" python3 - <<'PY'
import json
import os
data = json.loads(os.environ["PAYLOAD_BODY"])
fields = {field.get("name"): field.get("value") for field in data.get("payload", {}).get("fields", [])}
if fields != {"client_id": os.environ["EXPECTED_CLIENT_ID"], "client_secret": os.environ["EXPECTED_CLIENT_SECRET"]}:
    raise SystemExit("one-time OAuth credential payload was not preserved exactly")
PY
payload_second="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links/consume" \
  -H "Content-Type: application/json" \
  --data "{\"token\":\"${payload_token}\"}")"
assert_status "$(status_of "${payload_second}")" "410" "OAuth credential payload second consume"
after_client_count="$(db_scalar 'SELECT COUNT(*) FROM api_clients;')"
after_client_row="$(db_scalar "SELECT md5(row_to_json(api_clients)::text) FROM api_clients WHERE id = '${api_client_uuid}';")"
if [[ "${before_client_count}" != "${after_client_count}" || "${before_client_row}" != "${after_client_row}" ]]; then
  echo "delivered Client ID or Client Secret fields modified API client state" >&2
  exit 1
fi

# 9. Browser logout is a CSRF-protected redirect to /login.
logout_status="$(curl -sS -b "${cookie_jar}" -c "${cookie_jar}" -D "${tmpdir}/logout.headers" -o "${tmpdir}/logout.body" -w '%{http_code}' \
  -X POST "${BASE_URL}/logout" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "csrf_token=${csrf_token}")"
assert_status "${logout_status}" "303" "browser logout"
if ! grep -Eqi '^Location: /login\r?$' "${tmpdir}/logout.headers"; then
  echo "browser logout did not redirect to /login" >&2
  exit 1
fi

# 10. Sensitive request material and credentials never appear in application logs.
logs="$(compose_logs)"
for sensitive in \
  "${no_smtp_marker}" "${disabled_marker}" "${failed_email_marker}" \
  "${smtp_password_marker}" "${api_client_secret}" "${session_token}" \
  "${payload_client_id}" "${payload_client_secret}" \
  "${no_smtp_token}" "${disabled_token}" "${payload_token}" "${ADMIN_KEY}"; do
  if [[ -n "${sensitive}" ]] && grep -F "${sensitive}" <<<"${logs}" >/dev/null; then
    echo "sensitive QA value appeared in application logs" >&2
    exit 1
  fi
done
if grep -Eiq 'authorization["=: ]' <<<"${logs}"; then
  echo "Authorization header material appeared in application logs" >&2
  exit 1
fi

echo "QA regression test passed (10/10 checks, isolated stack)."
