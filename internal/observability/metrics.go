package observability

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	Registry               *prometheus.Registry
	SecretCreated          prometheus.Counter
	SecretConsumed         prometheus.Counter
	SecretUnavailable      prometheus.Counter
	SecretRevoked          prometheus.Counter
	SecretExpired          prometheus.Counter
	LoginFailures          prometheus.Counter
	CSRFFailures           prometheus.Counter
	RateLimitEvents        *prometheus.CounterVec
	VaultErrors            prometheus.Counter
	VaultDuration          *prometheus.HistogramVec
	DatabaseDuration       *prometheus.HistogramVec
	ConsumeDuration        prometheus.Histogram
	CleanupDuration        prometheus.Histogram
	CleanupDeletions       *prometheus.CounterVec
	SMTPConnectionTests    *prometheus.CounterVec
	SMTPConnectionErrors   *prometheus.CounterVec
	EmailTestDeliveries    *prometheus.CounterVec
	SMTPConnectionDuration *prometheus.HistogramVec
	EmailDeliveryRequested *prometheus.CounterVec
	EmailDeliverySucceeded *prometheus.CounterVec
	EmailDeliveryFailed    *prometheus.CounterVec
	EmailDeliveryRetry     *prometheus.CounterVec
	EmailDeliveryDuration  *prometheus.HistogramVec
	StaleLeaseRecovery     prometheus.Counter
	ActiveSecrets          prometheus.Gauge
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
		SMTPConnectionTests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "secureshare_smtp_connection_test_total",
			Help: "Total SMTP connection tests by result and encryption mode.",
		}, []string{"result", "encryption_mode"}),
		SMTPConnectionErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "secureshare_smtp_connection_errors_total",
			Help: "Total SMTP connection test errors by safe category and encryption mode.",
		}, []string{"error_category", "encryption_mode"}),
		EmailTestDeliveries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "secureshare_email_test_delivery_total",
			Help: "Total SMTP test email deliveries by result.",
		}, []string{"result"}),
		SMTPConnectionDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "secureshare_smtp_connection_duration_seconds",
			Help:    "SMTP connection test duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"result", "encryption_mode"}),
		EmailDeliveryRequested: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "secureshare_email_delivery_requested_total",
			Help: "Total requested one-time-link email deliveries.",
		}, []string{"template_source"}),
		EmailDeliverySucceeded: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "secureshare_email_delivery_succeeded_total",
			Help: "Total successful one-time-link email deliveries.",
		}, []string{"template_source"}),
		EmailDeliveryFailed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "secureshare_email_delivery_failed_total",
			Help: "Total failed one-time-link email deliveries by safe category and template source.",
		}, []string{"error_category", "template_source"}),
		EmailDeliveryRetry: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "secureshare_email_delivery_retry_total",
			Help: "Total one-time-link email retry attempts by result and template source.",
		}, []string{"result", "template_source"}),
		EmailDeliveryDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "secureshare_email_delivery_duration_seconds",
			Help:    "One-time-link email delivery duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"result", "error_category", "template_source"}),
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
		m.SMTPConnectionTests,
		m.SMTPConnectionErrors,
		m.EmailTestDeliveries,
		m.SMTPConnectionDuration,
		m.EmailDeliveryRequested,
		m.EmailDeliverySucceeded,
		m.EmailDeliveryFailed,
		m.EmailDeliveryRetry,
		m.EmailDeliveryDuration,
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
	for _, mode := range []string{"starttls", "tls", "none"} {
		for _, result := range []string{"success", "failed"} {
			m.SMTPConnectionTests.WithLabelValues(result, mode)
			m.SMTPConnectionDuration.WithLabelValues(result, mode)
		}
		for _, category := range []string{"SMTP_CONFIGURATION_ERROR", "SMTP_CONNECTION_FAILED", "SMTP_TLS_FAILED", "SMTP_AUTHENTICATION_FAILED", "SMTP_TIMEOUT", "SMTP_DELIVERY_FAILED"} {
			m.SMTPConnectionErrors.WithLabelValues(category, mode)
		}
	}
	for _, result := range []string{"success", "failed"} {
		m.EmailTestDeliveries.WithLabelValues(result)
	}
	for _, source := range []string{"fallback", "global_default", "per_delivery"} {
		m.EmailDeliveryRequested.WithLabelValues(source)
		m.EmailDeliverySucceeded.WithLabelValues(source)
		for _, result := range []string{"success", "failed", "rate_limited"} {
			m.EmailDeliveryRetry.WithLabelValues(result, source)
		}
		for _, category := range []string{"SMTP_CONFIGURATION_ERROR", "SMTP_CONNECTION_FAILED", "SMTP_TLS_FAILED", "SMTP_AUTHENTICATION_FAILED", "SMTP_RECIPIENT_REJECTED", "SMTP_TIMEOUT", "SMTP_DELIVERY_FAILED"} {
			m.EmailDeliveryFailed.WithLabelValues(category, source)
			for _, result := range []string{"sent", "failed"} {
				m.EmailDeliveryDuration.WithLabelValues(result, category, source)
			}
		}
		m.EmailDeliveryDuration.WithLabelValues("sent", "none", source)
	}
	return m
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
