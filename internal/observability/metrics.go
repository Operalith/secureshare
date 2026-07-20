package observability

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	Registry           *prometheus.Registry
	SecretCreated      prometheus.Counter
	SecretConsumed     prometheus.Counter
	SecretUnavailable  prometheus.Counter
	SecretRevoked      prometheus.Counter
	SecretExpired      prometheus.Counter
	LoginFailures      prometheus.Counter
	CSRFFailures       prometheus.Counter
	RateLimitEvents    *prometheus.CounterVec
	VaultErrors        prometheus.Counter
	VaultDuration      *prometheus.HistogramVec
	DatabaseDuration   *prometheus.HistogramVec
	ConsumeDuration    prometheus.Histogram
	CleanupDuration    prometheus.Histogram
	CleanupDeletions   *prometheus.CounterVec
	StaleLeaseRecovery prometheus.Counter
	ActiveSecrets      prometheus.Gauge
}

func New() *Metrics {
	registry := prometheus.NewRegistry()
	m := &Metrics{
		Registry: registry,
		SecretCreated: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "secureshare_secret_created_total",
			Help: "Total number of created secret deliveries.",
		}),
		SecretConsumed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "secureshare_secret_consumed_total",
			Help: "Total number of successfully consumed secret deliveries.",
		}),
		SecretUnavailable: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "secureshare_secret_unavailable_total",
			Help: "Total number of unavailable reveal attempts.",
		}),
		SecretRevoked: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "secureshare_secret_revoked_total",
			Help: "Total number of revoked secret deliveries.",
		}),
		SecretExpired: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "secureshare_secret_expired_total",
			Help: "Total number of secret deliveries marked expired by cleanup.",
		}),
		LoginFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "secureshare_login_failures_total",
			Help: "Total number of failed admin login attempts.",
		}),
		CSRFFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "secureshare_csrf_failures_total",
			Help: "Total number of rejected browser CSRF validations.",
		}),
		RateLimitEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "secureshare_rate_limit_events_total",
			Help: "Total number of rejected requests due to rate limits.",
		}, []string{"area"}),
		VaultErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "secureshare_vault_errors_total",
			Help: "Total number of Vault Transit errors.",
		}),
		VaultDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "secureshare_vault_latency_seconds",
			Help:    "Vault operation latency in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"operation"}),
		DatabaseDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "secureshare_database_latency_seconds",
			Help:    "Database operation latency in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"operation"}),
		ConsumeDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "secureshare_consume_duration_seconds",
			Help:    "Secret consume duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}),
		CleanupDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "secureshare_cleanup_duration_seconds",
			Help:    "Cleanup run duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}),
		CleanupDeletions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "secureshare_cleanup_deletions_total",
			Help: "Total records or payloads removed by cleanup.",
		}, []string{"kind"}),
		StaleLeaseRecovery: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "secureshare_stale_lease_recovery_total",
			Help: "Total stale consuming leases restored to active by cleanup.",
		}),
		ActiveSecrets: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "secureshare_active_secrets",
			Help: "Current active non-expired secret deliveries.",
		}),
	}
	registry.MustRegister(
		m.SecretCreated,
		m.SecretConsumed,
		m.SecretUnavailable,
		m.SecretRevoked,
		m.SecretExpired,
		m.LoginFailures,
		m.CSRFFailures,
		m.RateLimitEvents,
		m.VaultErrors,
		m.VaultDuration,
		m.DatabaseDuration,
		m.ConsumeDuration,
		m.CleanupDuration,
		m.CleanupDeletions,
		m.StaleLeaseRecovery,
		m.ActiveSecrets,
	)
	for _, area := range []string{"login", "create", "prepare", "consume"} {
		m.RateLimitEvents.WithLabelValues(area)
	}
	for _, operation := range []string{"encrypt", "decrypt"} {
		m.VaultDuration.WithLabelValues(operation)
	}
	for _, operation := range []string{
		"insert_delivery",
		"metadata",
		"list",
		"dashboard",
		"recent_activity",
		"revoke",
		"cleanup",
		"cleanup_worker",
		"prepare",
		"begin_consume",
		"record_password_failure",
		"restore_consume",
		"complete_consume",
		"record_audit",
	} {
		m.DatabaseDuration.WithLabelValues(operation)
	}
	for _, kind := range []string{"payload", "audit"} {
		m.CleanupDeletions.WithLabelValues(kind)
	}
	return m
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
