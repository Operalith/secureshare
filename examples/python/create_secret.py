#!/usr/bin/env python3
import base64
import json
import os
import sys
import urllib.error
import urllib.request


def env(name, default=None):
    value = os.environ.get(name, default)
    if value is None or value == "":
        print(f"{name} is required", file=sys.stderr)
        sys.exit(2)
    return value


base_url = env("SECURESHARE_BASE_URL", "http://localhost:8080").rstrip("/")
client_id = env("SECURESHARE_CLIENT_ID")
client_secret = env("SECURESHARE_CLIENT_SECRET")

payload = {
    "title": "Example login",
    "expires_in_seconds": 3600,
    "payload": {
        "type": "structured",
        "fields": [
            {"name": "username", "label": "Username", "value": "example-user", "sensitive": False, "multiline": False},
            {"name": "password", "label": "Password", "value": "example-password", "sensitive": True, "multiline": False},
        ],
    },
}

raw = json.dumps(payload).encode("utf-8")
token = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
request = urllib.request.Request(
    f"{base_url}/api/v1/secret-links",
    data=raw,
    headers={
        "Authorization": f"Basic {token}",
        "Content-Type": "application/json",
    },
    method="POST",
)

try:
    with urllib.request.urlopen(request, timeout=15) as response:
        body = response.read()
except urllib.error.HTTPError as exc:
    print(f"SecureShare returned HTTP {exc.code}", file=sys.stderr)
    sys.exit(1)

print(json.loads(body)["url"])
