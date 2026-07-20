package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"secureshare/internal/auth"
	"secureshare/internal/cleanup"
	"secureshare/internal/config"
	"secureshare/internal/crypto"
	"secureshare/internal/database"
	"secureshare/internal/delivery"
	server "secureshare/internal/http"
	"secureshare/internal/observability"
	"secureshare/internal/ratelimit"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration failed", "error", err)
		os.Exit(1)
	}

	logger := newLogger(cfg)
	slog.SetDefault(logger)

	db, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := database.RunMigrations(ctx, db, cfg.MigrationsDir); err != nil {
		logger.Error("database migrations failed", "error", err)
		os.Exit(1)
	}

	vaultClient, err := crypto.NewVaultTransit(cfg.VaultAddr, cfg.VaultToken, cfg.VaultTransitKey)
	if err != nil {
		logger.Error("vault client setup failed", "error", err)
		os.Exit(1)
	}

	repo := delivery.NewRepository(db)
	metrics := observability.New()
	secrets := delivery.NewService(cfg, repo, vaultClient, metrics, logger)
	sessions := auth.NewSessionManager(cfg.SessionSecret, cfg.CSRFSecret, cfg.SessionTTL, cfg.SessionIdleTimeout, cfg.CookieSecure)
	limiters := ratelimit.NewRegistry()
	app := server.New(server.Dependencies{
		Config:   cfg,
		Logger:   logger,
		Auth:     sessions,
		Delivery: secrets,
		DB:       db,
		Vault:    vaultClient,
		Metrics:  metrics,
		Limits:   limiters,
	})

	cleaner := cleanup.NewWorker(cfg, repo, metrics, logger)
	go cleaner.Run(ctx)

	srv := &http.Server{
		Addr:              cfg.AppAddr,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("secureshare starting", "addr", cfg.AppAddr, "env", cfg.AppEnv)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped unexpectedly", "error", err)
			os.Exit(1)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	logger.Info("secureshare stopped")
}

func newLogger(cfg config.Config) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}
