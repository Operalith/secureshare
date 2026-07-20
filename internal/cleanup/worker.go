package cleanup

import (
	"context"
	"log/slog"

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
	expired, cleared, restored, err := w.repo.Cleanup(ctx, w.cfg.ConsumedRetention, w.cfg.ExpiredRetention, w.cfg.RevokedRetention, w.cfg.ConsumingLeaseTTL)
	if err != nil {
		w.logger.Warn("cleanup failed", "error", err)
		return
	}
	if expired > 0 {
		w.metrics.SecretExpired.Add(float64(expired))
	}
	if active, err := w.repo.CountActive(ctx); err == nil {
		w.metrics.ActiveSecrets.Set(active)
	}
	w.logger.Debug("cleanup completed", "expired", expired, "payloads_cleared", cleared, "leases_restored", restored)
}
