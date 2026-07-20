# Go Example

Run:

```bash
export SECURESHARE_BASE_URL=http://localhost:8080
export SECURESHARE_CLIENT_ID=ssc_example
export SECURESHARE_CLIENT_SECRET=sscs_example
go run ./examples/go
```

The program uses a timeout, sends Basic auth, handles non-2xx responses, and prints only the returned one-time URL.
