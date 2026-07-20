package observability

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsExposeProductionSignals(t *testing.T) {
	metrics := New()
	rec := httptest.NewRecorder()

	metrics.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))

	body := rec.Body.String()
	for _, name := range []string{
		"secureshare_login_failures_total",
		"secureshare_csrf_failures_total",
		"secureshare_rate_limit_events_total",
		"secureshare_vault_latency_seconds",
		"secureshare_database_latency_seconds",
		"secureshare_cleanup_duration_seconds",
		"secureshare_cleanup_deletions_total",
		"secureshare_stale_lease_recovery_total",
	} {
		if !strings.Contains(body, name) {
			t.Fatalf("expected metric %s to be exposed", name)
		}
	}
}
