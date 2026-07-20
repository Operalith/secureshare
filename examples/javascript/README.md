# JavaScript Example

Run with Node.js 18 or newer:

```bash
export SECURESHARE_BASE_URL=http://localhost:8080
export SECURESHARE_CLIENT_ID=ssc_example
export SECURESHARE_CLIENT_SECRET=sscs_example
node examples/javascript/create-secret.mjs
```

The script uses the built-in `fetch`, aborts after a timeout, handles non-2xx responses, and prints only the returned one-time URL.
