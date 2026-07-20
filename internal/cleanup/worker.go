package cleanup

import (
	"context"
	"log/slog"
	"time"

	"secureshare/internal/config"
	"secureshare/internal/delivery"
	"secureshare/internal/observability"
)

type Worker struct {
	cfg     config.Config
	repo    *delivery.Repository
	metrics *observability.Metrics
	logger  *slog.Logger
}

func NewWorker(cfg config.Config, repo *delivery.Repository, metrics *observability.Metrics, logger *slog.Logger) *Worker {
	return &Worker{cfg: cfg, repo: repo, metrics: metrics, logger: logger}
}

func (w *Worker) Run(ctx context.Context) {
	w.runOnce(ctx)
	ticker := NewTicker(w.cfg.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.runOnce(ctx)
		}
	}
}

func (w *Worker) runOnce(ctx context.Context) {
	start := time.Now()
	result, err := w.repo.Cleanup(ctx, w.cfg.ConsumedRetention, w.cfg.ExpiredRetention, w.cfg.RevokedRetention, w.cfg.ConsumingLeaseTTL, w.cfg.AuditRetention)
	elapsed := time.Since(start).Seconds()
	if w.metrics != nil {
		w.metrics.CleanupDuration.Observe(elapsed)
		w.metrics.DatabaseDuration.WithLabelValues("cleanup_worker").Observe(elapsed)
	}
	if err != nil {
		w.logger.Warn("cleanup failed", "error", err)
		return
	}
	if w.metrics != nil {
		if result.Expired > 0 {
			w.metrics.SecretExpired.Add(float64(result.Expired))
		}
		if result.PayloadsCleared > 0 {
			w.metrics.CleanupDeletions.WithLabelValues("payload").Add(float64(result.PayloadsCleared))
		}
		if result.AuditDeleted > 0 {
			w.metrics.CleanupDeletions.WithLabelValues("audit").Add(float64(result.AuditDeleted))
		}
		if result.LeasesRestored > 0 {
			w.metrics.StaleLeaseRecovery.Add(float64(result.LeasesRestored))
		}
		if active, err := w.repo.CountActive(ctx); err == nil {
			w.metrics.ActiveSecrets.Set(active)
		}
	}
	w.logger.Debug("cleanup completed", "expired", result.Expired, "payloads_cleared", result.PayloadsCleared, "leases_restored", result.LeasesRestored, "audit_deleted", result.AuditDeleted)
}
