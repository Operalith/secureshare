package middleware

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"secureshare/internal/config"
)

func TestSecurityHeaders(t *testing.T) {
	cfg := config.Config{RequestIPHashPepper: "pepper"}
	handler := SecurityHeaders(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/s", nil))

	headers := rec.Result().Header
	assertHeader(t, headers, "Cache-Control", "no-store")
	assertHeader(t, headers, "Referrer-Policy", "no-referrer")
	assertHeader(t, headers, "Content-Security-Policy", "default-src 'self'")
	assertHeader(t, headers, "X-Frame-Options", "DENY")
	assertHeader(t, headers, "X-Content-Type-Options", "nosniff")
}

func TestLoggingDoesNotRecordSensitiveValues(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	cfg := config.Config{RequestIPHashPepper: "pepper"}
	handler := Logging(logger, cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secret-links/consume", strings.NewReader(`{"token":"raw-token","password":"test-password"}`))
	req.Header.Set("Authorization", "Bearer test-api-key")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	output := logs.String()
	for _, sensitive := range []string{"raw-token", "test-password", "test-api-key", "Bearer", "http://localhost:8080/s#raw-token"} {
		if strings.Contains(output, sensitive) {
			t.Fatalf("log contained sensitive value %q: %s", sensitive, output)
		}
	}
}

func assertHeader(t *testing.T, headers http.Header, key string, wantContains string) {
	t.Helper()
	if got := headers.Get(key); !strings.Contains(got, wantContains) {
		t.Fatalf("%s = %q, want contains %q", key, got, wantContains)
	}
}
