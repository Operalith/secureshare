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
ADMIN_USERNAME="${BOOTSTRAP_ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${BOOTSTRAP_ADMIN_PASSWORD:-change-me-now}"
CANARY="security-canary-$(date +%s)-$$"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

body_of() {
  sed '/^__STATUS__/d' <<<"$1"
}

status_of() {
  awk -F'__STATUS__' '/__STATUS__/ {print $2}' <<<"$1"
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
  exit 1
}

create_secret() {
  local title="$1"
  local secret_json="$2"
  local extra="${3:-}"
  local payload
  payload="{\"title\":\"${title}\",\"secret\":${secret_json},\"expires_in_seconds\":900,\"max_failed_attempts\":5${extra}}"
  local result
  result="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links" \
    -H "Authorization: Bearer ${ADMIN_KEY}" \
    -H "Content-Type: application/json" \
    --data "${payload}")"
  assert_status "$(status_of "${result}")" "201" "create ${title}"
  body_of "${result}"
}

token_from_body() {
  local url
  url="$(json_get url)"
  printf '%s' "${url##*#}"
}

wait_ready

unauth="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links" -H "Content-Type: application/json" --data '{"secret":"blocked"}')"
assert_status "$(status_of "${unauth}")" "401" "unauthorized create"

bad_login="$(request_with_status -X POST "${BASE_URL}/api/v1/auth/login" -H "Content-Type: application/json" --data '{"login":"admin","password":"wrong"}')"
assert_status "$(status_of "${bad_login}")" "401" "invalid admin login"

cookie_jar="${tmpdir}/cookies.txt"
login="$(request_with_status -c "${cookie_jar}" -X POST "${BASE_URL}/api/v1/auth/login" -H "Content-Type: application/json" --data "{\"login\":\"${ADMIN_USERNAME}\",\"password\":\"${ADMIN_PASSWORD}\"}")"
assert_status "$(status_of "${login}")" "200" "valid login"
csrf_token="$(body_of "${login}" | json_get csrf_token)"
if [[ -z "${csrf_token}" ]]; then
  echo "login did not return csrf_token" >&2
  exit 1
fi

csrf_block="$(request_with_status -b "${cookie_jar}" -X POST "${BASE_URL}/api/v1/secret-links" -H "Content-Type: application/json" --data '{"secret":"csrf-blocked","expires_in_seconds":900}')"
assert_status "$(status_of "${csrf_block}")" "403" "CSRF rejection"

large_secret="$(python3 - <<'PY'
print("x" * (33 * 1024))
PY
)"
large="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links" -H "Authorization: Bearer ${ADMIN_KEY}" -H "Content-Type: application/json" --data "{\"secret\":\"${large_secret}\",\"expires_in_seconds\":900}")"
assert_status "$(status_of "${large}")" "413" "payload too large"

bad_type="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links" -H "Authorization: Bearer ${ADMIN_KEY}" -H "Content-Type: text/plain" --data '{"secret":"wrong-type"}')"
assert_status "$(status_of "${bad_type}")" "415" "invalid content type"

first_body="$(create_secret "security-first" "{\"value\":\"${CANARY}-first\"}")"
first_token="$(token_from_body <<<"${first_body}")"
first_consume="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links/consume" -H "Content-Type: application/json" --data "{\"token\":\"${first_token}\"}")"
assert_status "$(status_of "${first_consume}")" "200" "first consume"
second_consume="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links/consume" -H "Content-Type: application/json" --data "{\"token\":\"${first_token}\"}")"
assert_status "$(status_of "${second_consume}")" "410" "second consume"

concurrent_body="$(create_secret "security-concurrent" "{\"value\":\"${CANARY}-concurrent\"}")"
concurrent_token="$(token_from_body <<<"${concurrent_body}")"
for i in $(seq 1 20); do
  (
    curl -sS -o /dev/null -w "%{http_code}\n" -X POST "${BASE_URL}/api/v1/secret-links/consume" \
      -H "Content-Type: application/json" \
      -H "X-Forwarded-For: 203.0.113.${i}" \
      --data "{\"token\":\"${concurrent_token}\"}" >"${tmpdir}/concurrent-${i}.status"
  ) &
done
wait
successes="$(cat "${tmpdir}"/concurrent-*.status | grep -c '^200$' || true)"
unavailable="$(cat "${tmpdir}"/concurrent-*.status | grep -Ec '^(410|409)$' || true)"
if [[ "${successes}" != "1" || "${unavailable}" != "19" ]]; then
  echo "concurrent consume expected 1 success and 19 unavailable, got ${successes}/${unavailable}" >&2
  cat "${tmpdir}"/concurrent-*.status >&2
  exit 1
fi

expired_body="$(create_secret "security-expired" "{\"value\":\"${CANARY}-expired\"}" ",\"expires_in_seconds\":1")"
expired_token="$(token_from_body <<<"${expired_body}")"
sleep 2
expired_consume="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links/consume" -H "Content-Type: application/json" --data "{\"token\":\"${expired_token}\"}")"
assert_status "$(status_of "${expired_consume}")" "410" "expired token"

revoked_body="$(create_secret "security-revoked" "{\"value\":\"${CANARY}-revoked\"}")"
revoked_id="$(json_get id <<<"${revoked_body}")"
revoked_token="$(token_from_body <<<"${revoked_body}")"
revoke_result="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links/${revoked_id}/revoke" -H "Authorization: Bearer ${ADMIN_KEY}" --data '{}')"
assert_status "$(status_of "${revoke_result}")" "200" "revoke"
revoked_consume="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links/consume" -H "Content-Type: application/json" --data "{\"token\":\"${revoked_token}\"}")"
assert_status "$(status_of "${revoked_consume}")" "410" "revoked token"

password_body="$(create_secret "security-password" "{\"value\":\"${CANARY}-password\"}" ",\"password\":\"correct-password\",\"max_failed_attempts\":2")"
password_token="$(token_from_body <<<"${password_body}")"
for attempt in 1 2; do
  wrong="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links/consume" -H "Content-Type: application/json" --data "{\"token\":\"${password_token}\",\"password\":\"wrong-${attempt}\"}")"
  assert_status "$(status_of "${wrong}")" "410" "password failure ${attempt}"
done
locked="$(request_with_status -X POST "${BASE_URL}/api/v1/secret-links/consume" -H "Content-Type: application/json" --data "{\"token\":\"${password_token}\",\"password\":\"correct-password\"}")"
assert_status "$(status_of "${locked}")" "410" "password lockout"

headers="$(mktemp)"
curl -sS -D "${headers}" -o /dev/null "${BASE_URL}/s"
grep -qi '^Cache-Control: .*no-store' "${headers}"
grep -qi '^Referrer-Policy: no-referrer' "${headers}"
grep -qi '^Content-Security-Policy:' "${headers}"
grep -qi '^X-Frame-Options: DENY' "${headers}"
grep -qi '^X-Content-Type-Options: nosniff' "${headers}"

if docker compose -f "${ROOT_DIR}/docker-compose.yml" logs --no-color app 2>/dev/null | grep -F "${CANARY}" >/dev/null; then
  echo "canary secret appeared in app logs" >&2
  exit 1
fi
if docker compose -f "${ROOT_DIR}/docker-compose.yml" logs --no-color app 2>/dev/null | grep -F "${first_token}" >/dev/null; then
  echo "raw token appeared in app logs" >&2
  exit 1
fi

echo "Security test passed."
