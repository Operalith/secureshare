package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultMaxSecretBytes = 32 * 1024
)

type Config struct {
	AppEnv                 string
	AppAddr                string
	AppBaseURL             string
	DatabaseURL            string
	VaultAddr              string
	VaultToken             string
	VaultTransitKey        string
	AdminAPIKey            string
	TokenHMACPepper        string
	SessionSecret          string
	CSRFSecret             string
	BootstrapAdminUsername string
	BootstrapAdminEmail    string
	BootstrapAdminPassword string
	SessionTTL             time.Duration
	SessionIdleTimeout     time.Duration
	CookieSecure           bool
	MaxSecretTTL           time.Duration
	DefaultSecretTTL       time.Duration
	ConsumingLeaseTTL      time.Duration
	CleanupInterval        time.Duration
	ConsumedRetention      time.Duration
	ExpiredRetention       time.Duration
	RevokedRetention       time.Duration
	AuditRetention         time.Duration
	LogLevel               string
	MetricsEnabled         bool
	MigrationsDir          string
	MaxSecretBytes         int64
	RequestIPHashPepper    string
	EnableHSTS             bool
}

func Load() (Config, error) {
	cfg := Config{
		AppEnv:                 getenv("APP_ENV", "development"),
		AppAddr:                getenv("APP_ADDR", ":8080"),
		AppBaseURL:             strings.TrimRight(getenv("APP_BASE_URL", "http://localhost:8080"), "/"),
		DatabaseURL:            getenv("DATABASE_URL", "postgres://secureshare:secureshare@localhost:5432/secureshare?sslmode=disable"),
		VaultAddr:              getenv("VAULT_ADDR", "http://localhost:8200"),
		VaultToken:             getenv("VAULT_TOKEN", "root"),
		VaultTransitKey:        getenv("VAULT_TRANSIT_KEY", "secureshare"),
		AdminAPIKey:            getenv("SECURESHARE_ADMIN_API_KEY", "change-me"),
		TokenHMACPepper:        getenv("TOKEN_HMAC_PEPPER", "replace-with-a-long-random-value"),
		SessionSecret:          getenv("SESSION_SECRET", "replace-with-a-long-random-value"),
		CSRFSecret:             getenv("CSRF_SECRET", "replace-with-a-long-random-value"),
		BootstrapAdminUsername: getenv("BOOTSTRAP_ADMIN_USERNAME", "admin"),
		BootstrapAdminEmail:    getenv("BOOTSTRAP_ADMIN_EMAIL", "admin@example.local"),
		BootstrapAdminPassword: getenv("BOOTSTRAP_ADMIN_PASSWORD", "change-me-now"),
		LogLevel:               strings.ToLower(getenv("LOG_LEVEL", "info")),
		MetricsEnabled:         getenvBool("METRICS_ENABLED", true),
		MigrationsDir:          getenv("MIGRATIONS_DIR", "migrations"),
		MaxSecretBytes:         getenvInt64("MAX_SECRET_BYTES", DefaultMaxSecretBytes),
		RequestIPHashPepper:    getenv("REQUEST_IP_HASH_PEPPER", ""),
	}

	var err error
	if cfg.MaxSecretTTL, err = getenvDuration("MAX_SECRET_TTL", 168*time.Hour); err != nil {
		return cfg, err
	}
	if cfg.DefaultSecretTTL, err = getenvDuration("DEFAULT_SECRET_TTL", 24*time.Hour); err != nil {
		return cfg, err
	}
	if cfg.ConsumingLeaseTTL, err = getenvDuration("CONSUMING_LEASE_TTL", 30*time.Second); err != nil {
		return cfg, err
	}
	if cfg.CleanupInterval, err = getenvDuration("CLEANUP_INTERVAL", 5*time.Minute); err != nil {
		return cfg, err
	}
	if cfg.ConsumedRetention, err = getenvDuration("CONSUMED_PAYLOAD_RETENTION", 0); err != nil {
		return cfg, err
	}
	if cfg.ExpiredRetention, err = getenvDuration("EXPIRED_PAYLOAD_RETENTION", 24*time.Hour); err != nil {
		return cfg, err
	}
	if cfg.RevokedRetention, err = getenvDuration("REVOKED_PAYLOAD_RETENTION", 24*time.Hour); err != nil {
		return cfg, err
	}
	if cfg.AuditRetention, err = getenvDuration("AUDIT_EVENT_RETENTION", 90*24*time.Hour); err != nil {
		return cfg, err
	}
	if cfg.SessionTTL, err = getenvDuration("SESSION_TTL", 12*time.Hour); err != nil {
		return cfg, err
	}
	if cfg.SessionIdleTimeout, err = getenvDuration("SESSION_IDLE_TIMEOUT", 30*time.Minute); err != nil {
		return cfg, err
	}

	cfg.CookieSecure = getenvBool("COOKIE_SECURE", cfg.AppEnv != "development")
	cfg.EnableHSTS = cfg.AppEnv == "production"
	if cfg.RequestIPHashPepper == "" {
		cfg.RequestIPHashPepper = cfg.SessionSecret
	}

	return cfg, cfg.Validate()
}

func (c Config) Validate() error {
	var errs []error
	required := map[string]string{
		"APP_BASE_URL":              c.AppBaseURL,
		"DATABASE_URL":              c.DatabaseURL,
		"VAULT_ADDR":                c.VaultAddr,
		"VAULT_TOKEN":               c.VaultToken,
		"VAULT_TRANSIT_KEY":         c.VaultTransitKey,
		"SECURESHARE_ADMIN_API_KEY": c.AdminAPIKey,
		"TOKEN_HMAC_PEPPER":         c.TokenHMACPepper,
		"SESSION_SECRET":            c.SessionSecret,
		"CSRF_SECRET":               c.CSRFSecret,
		"REQUEST_IP_HASH_PEPPER":    c.RequestIPHashPepper,
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			errs = append(errs, fmt.Errorf("%s is required", name))
		}
	}
	if _, err := url.ParseRequestURI(c.AppBaseURL); err != nil {
		errs = append(errs, fmt.Errorf("APP_BASE_URL must be a valid URL: %w", err))
	}
	if c.MaxSecretTTL <= 0 {
		errs = append(errs, errors.New("MAX_SECRET_TTL must be positive"))
	}
	if c.DefaultSecretTTL <= 0 || c.DefaultSecretTTL > c.MaxSecretTTL {
		errs = append(errs, errors.New("DEFAULT_SECRET_TTL must be positive and no greater than MAX_SECRET_TTL"))
	}
	if c.ConsumingLeaseTTL <= 0 {
		errs = append(errs, errors.New("CONSUMING_LEASE_TTL must be positive"))
	}
	if c.CleanupInterval <= 0 {
		errs = append(errs, errors.New("CLEANUP_INTERVAL must be positive"))
	}
	if c.SessionTTL <= 0 || c.SessionIdleTimeout <= 0 || c.SessionIdleTimeout > c.SessionTTL {
		errs = append(errs, errors.New("SESSION_IDLE_TIMEOUT must be positive and no greater than SESSION_TTL"))
	}
	if c.MaxSecretBytes <= 0 || c.MaxSecretBytes > 1024*1024 {
		errs = append(errs, errors.New("MAX_SECRET_BYTES must be between 1 byte and 1 MiB"))
	}
	if c.BootstrapAdminUsername != "" || c.BootstrapAdminEmail != "" || c.BootstrapAdminPassword != "" {
		if strings.TrimSpace(c.BootstrapAdminUsername) == "" {
			errs = append(errs, errors.New("BOOTSTRAP_ADMIN_USERNAME is required when bootstrap admin is configured"))
		}
		if strings.TrimSpace(c.BootstrapAdminEmail) == "" || !strings.Contains(c.BootstrapAdminEmail, "@") {
			errs = append(errs, errors.New("BOOTSTRAP_ADMIN_EMAIL must be a valid email-like value"))
		}
		if strings.TrimSpace(c.BootstrapAdminPassword) == "" {
			errs = append(errs, errors.New("BOOTSTRAP_ADMIN_PASSWORD is required when bootstrap admin is configured"))
		}
	}

	if c.AppEnv != "development" {
		if len(c.AdminAPIKey) < 32 || c.AdminAPIKey == "change-me" {
			errs = append(errs, errors.New("SECURESHARE_ADMIN_API_KEY must be strong outside development"))
		}
		if len(c.TokenHMACPepper) < 32 || strings.Contains(c.TokenHMACPepper, "replace-with") {
			errs = append(errs, errors.New("TOKEN_HMAC_PEPPER must be strong outside development"))
		}
		if len(c.SessionSecret) < 32 || strings.Contains(c.SessionSecret, "replace-with") {
			errs = append(errs, errors.New("SESSION_SECRET must be strong outside development"))
		}
		if len(c.CSRFSecret) < 32 || strings.Contains(c.CSRFSecret, "replace-with") {
			errs = append(errs, errors.New("CSRF_SECRET must be strong outside development"))
		}
		if !c.CookieSecure {
			errs = append(errs, errors.New("COOKIE_SECURE must be true outside development"))
		}
		if isWeakBootstrapPassword(c.BootstrapAdminPassword) {
			errs = append(errs, errors.New("BOOTSTRAP_ADMIN_PASSWORD must be strong outside development"))
		}
	}

	return errors.Join(errs...)
}

func isWeakBootstrapPassword(password string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(password))
	if len(trimmed) < 12 {
		return true
	}
	switch trimmed {
	case "change-me", "change-me-now", "password", "password123", "admin", "admin123", "secureshare":
		return true
	default:
		return strings.Contains(trimmed, "replace-with")
	}
}

func getenv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getenvInt64(key string, fallback int64) int64 {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func getenvDuration(key string, fallback time.Duration) (time.Duration, error) {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a Go duration: %w", key, err)
	}
	return parsed, nil
}
