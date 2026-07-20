# Python Example

Run:

```bash
export SECURESHARE_BASE_URL=http://localhost:8080
export SECURESHARE_CLIENT_ID=ssc_example
export SECURESHARE_CLIENT_SECRET=sscs_example
python3 examples/python/create_secret.py
```

The script uses only Python standard libraries, verifies TLS through the default HTTPS stack, applies a timeout, and prints only the returned one-time URL.
