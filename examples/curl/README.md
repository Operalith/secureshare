# Curl Example

Set credentials:

```bash
export SECURESHARE_BASE_URL=http://localhost:8080
export SECURESHARE_CLIENT_ID=ssc_example
export SECURESHARE_CLIENT_SECRET=sscs_example
```

Create a username/password link:

```bash
curl -fsS -X POST "${SECURESHARE_BASE_URL}/api/v1/secret-links" \
  -u "${SECURESHARE_CLIENT_ID}:${SECURESHARE_CLIENT_SECRET}" \
  -H "Content-Type: application/json" \
  --connect-timeout 5 \
  --max-time 15 \
  -d '{
    "title": "Example login",
    "expires_in_seconds": 3600,
    "payload": {
      "type": "structured",
      "fields": [
        {"name":"username","label":"Username","value":"example-user","sensitive":false,"multiline":false},
        {"name":"password","label":"Password","value":"example-password","sensitive":true,"multiline":false}
      ]
    }
  }' | python3 -c 'import json,sys; print(json.load(sys.stdin)["url"])'
```

The command prints only the one-time URL. Do not enable shell tracing while passing real secret payloads.
