#!/bin/sh
set -eu

: "${VAULT_ADDR:?VAULT_ADDR is required}"
: "${VAULT_TOKEN:?VAULT_TOKEN is required}"
: "${VAULT_TRANSIT_KEY:=secureshare}"

export VAULT_ADDR VAULT_TOKEN

echo "Waiting for Vault..."
until vault status >/dev/null 2>&1; do
  sleep 1
done

if ! vault secrets list | grep -q '^transit/'; then
  vault secrets enable transit >/dev/null
fi

if ! vault read "transit/keys/${VAULT_TRANSIT_KEY}" >/dev/null 2>&1; then
  vault write -f "transit/keys/${VAULT_TRANSIT_KEY}" >/dev/null
fi

echo "Vault Transit key '${VAULT_TRANSIT_KEY}' is ready."
