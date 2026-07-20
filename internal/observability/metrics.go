package observability

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	Registry          *prometheus.Registry
	SecretCreated     prometheus.Counter
	SecretConsumed    prometheus.Counter
	SecretUnavailable prometheus.Counter
	SecretRevoked     prometheus.Counter
	SecretExpired     prometheus.Counter
	VaultErrors       prometheus.Counter
	ConsumeDuration   prometheus.Histogram
	ActiveSecrets     prometheus.Gauge
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
		VaultErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "secureshare_vault_errors_total",
			Help: "Total number of Vault Transit errors.",
		}),
		ConsumeDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "secureshare_consume_duration_seconds",
			Help:    "Secret consume duration in seconds.",
			Buckets: prometheus.DefBuckets,
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
		m.VaultErrors,
		m.ConsumeDuration,
		m.ActiveSecrets,
	)
	return m
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
