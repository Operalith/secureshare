package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidateRejectsDefaultTTLGreaterThanMax(t *testing.T) {
	cfg := validConfig()
	cfg.DefaultSecretTTL = 8 * 24 * time.Hour
	cfg.MaxSecretTTL = 7 * 24 * time.Hour
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateRejectsWeakProductionSecrets(t *testing.T) {
	cfg := validConfig()
	cfg.AppEnv = "production"
	cfg.AdminAPIKey = "change-me"
	cfg.TokenHMACPepper = "replace-with-a-long-random-value"
	cfg.SessionSecret = "replace-with-a-long-random-value"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "SECURESHARE_ADMIN_API_KEY") {
		t.Fatalf("expected admin key error, got %v", err)
	}
}

func validConfig() Config {
	return Config{
		AppEnv:              "development",
		AppAddr:             ":8080",
		AppBaseURL:          "http://localhost:8080",
		DatabaseURL:         "postgres://secureshare:secureshare@localhost:5432/secureshare?sslmode=disable",
		VaultAddr:           "http://localhost:8200",
		VaultToken:          "root",
		VaultTransitKey:     "secureshare",
		AdminAPIKey:         "change-me",
		TokenHMACPepper:     "replace-with-a-long-random-value-at-least-32-bytes",
		SessionSecret:       "replace-with-a-long-random-value-at-least-32-bytes",
		SessionTTL:          12 * time.Hour,
		MaxSecretTTL:        7 * 24 * time.Hour,
		DefaultSecretTTL:    24 * time.Hour,
		ConsumingLeaseTTL:   30 * time.Second,
		CleanupInterval:     5 * time.Minute,
		MaxSecretBytes:      DefaultMaxSecretBytes,
		RequestIPHashPepper: "replace-with-a-long-random-value-at-least-32-bytes",
	}
}
