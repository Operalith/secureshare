package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"secureshare/internal/auth"
	"secureshare/internal/config"
	"secureshare/internal/delivery"
	"secureshare/internal/observability"
	"secureshare/internal/ratelimit"
)

func TestLoginPageRendering(t *testing.T) {
	app := testServer()
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	body := rec.Body.String()
	for _, want := range []string{"SecureShare", "Admin sign in", "data-login-form", "Show"} {
		if !strings.Contains(body, want) {
			t.Fatalf("login page missing %q", want)
		}
	}
}

func TestAdminPagesRendering(t *testing.T) {
	app := testServer()
	cookie := loginCookie(t, app)
	for _, path := range []string{"/admin", "/admin/secrets/new", "/admin/secrets", "/admin/secrets/" + testUUID.String(), "/admin/status", "/admin/help"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			app.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s status = %d, want 200; body=%s", path, rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			if strings.Contains(body, "canary-secret-value") || strings.Contains(body, "vault:v1:canary") {
				t.Fatalf("%s leaked sensitive test value", path)
			}
		})
	}
}

func TestCreateFormRenderingModes(t *testing.T) {
	app := testServer()
	req := httptest.NewRequest(http.MethodGet, "/admin/secrets/new", nil)
	req.AddCookie(loginCookie(t, app))
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	body := rec.Body.String()
	for _, want := range []string{"data-secret-mode=\"structured\"", "data-secret-mode=\"plain\"", "Password attempt limit", "security-summary", "created-result"} {
		if !strings.Contains(body, want) {
			t.Fatalf("create form missing %q", want)
		}
	}
}

func TestRecipientRevealPageRendering(t *testing.T) {
	app := testServer()
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/s", nil))
	body := rec.Body.String()
	for _, want := range []string{"Reveal Secret", "unavailable-wrap", "/static/reveal.js", "This secret can only be viewed once"} {
		if !strings.Contains(body, want) {
			t.Fatalf("recipient page missing %q", want)
		}
	}
}

func TestNoExternalAssetsOrBrowserStorageUsage(t *testing.T) {
	for _, path := range []string{"../../web/templates/login.html", "../../web/templates/admin.html", "../../web/templates/new_secret.html", "../../web/templates/secret_list.html", "../../web/templates/recipient.html", "../../web/static/admin.js", "../../web/static/reveal.js"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		for _, forbidden := range []string{"https://", "http://", "localStorage", "sessionStorage", "indexedDB", "serviceWorker", "cdn"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains forbidden frontend reference %q", path, forbidden)
			}
		}
	}
}

func TestSecurityHeadersStillApplyToUIPages(t *testing.T) {
	app := testServer()
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/s", nil))
	headers := rec.Result().Header
	for key, want := range map[string]string{
		"Cache-Control":           "no-store",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": "default-src 'self'",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
	} {
		if got := headers.Get(key); !strings.Contains(got, want) {
			t.Fatalf("%s = %q, want contains %q", key, got, want)
		}
	}
}

func loginCookie(t *testing.T, app *Server) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"api_key":"change-me"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == auth.CookieName {
			return cookie
		}
	}
	t.Fatal("login did not set session cookie")
	return nil
}

func testServer() *Server {
	cfg := config.Config{
		AppEnv:              "development",
		AppBaseURL:          "http://localhost:8080",
		AdminAPIKey:         "change-me",
		TokenHMACPepper:     "test-pepper-with-enough-length",
		SessionSecret:       "test-session-secret-with-enough-length",
		SessionTTL:          time.Hour,
		RequestIPHashPepper: "ip-pepper-with-enough-length",
		MaxSecretTTL:        7 * 24 * time.Hour,
		DefaultSecretTTL:    24 * time.Hour,
		ConsumingLeaseTTL:   30 * time.Second,
		MaxSecretBytes:      config.DefaultMaxSecretBytes,
	}
	return New(Dependencies{
		Config:   cfg,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Auth:     auth.NewSessionManager(cfg.SessionSecret, cfg.SessionTTL, false),
		Delivery: delivery.NewService(cfg, &uiStore{}, &uiVault{}, observability.New(), slog.Default()),
		Metrics:  observability.New(),
		Limits:   ratelimit.NewRegistry(),
	})
}

var testUUID = uuid.MustParse("11111111-1111-4111-8111-111111111111")

type uiVault struct{}

func (v *uiVault) Encrypt(context.Context, []byte) (string, error) { return "vault:v1:canary", nil }
func (v *uiVault) Decrypt(context.Context, string) ([]byte, error) { return []byte(`{"ok":true}`), nil }
func (v *uiVault) Ready(context.Context) error                     { return nil }

type uiStore struct{}

func (s *uiStore) Insert(context.Context, delivery.InsertParams) error { return nil }

func (s *uiStore) Metadata(context.Context, uuid.UUID) (delivery.Metadata, error) {
	now := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
	consumed := now.Add(30 * time.Minute)
	return delivery.Metadata{
		ID:                 testUUID,
		Title:              "Merchant credentials",
		Description:        "Safe metadata only",
		RecipientReference: "merchant-1001",
		Status:             delivery.StatusConsumed,
		ExpiresAt:          now.Add(24 * time.Hour),
		ConsumedAt:         &consumed,
		CreatedBy:          "admin",
		CreatedAt:          now,
		UpdatedAt:          consumed,
		PasswordProtected:  true,
		FailedAttempts:     0,
		MaxFailedAttempts:  5,
	}, nil
}

func (s *uiStore) List(context.Context, delivery.ListOptions) (delivery.ListResult, error) {
	meta, _ := s.Metadata(context.Background(), testUUID)
	return delivery.ListResult{
		Items: []delivery.Metadata{meta},
		Pagination: delivery.Pagination{
			Page:       1,
			PageSize:   25,
			TotalItems: 1,
			TotalPages: 1,
		},
	}, nil
}

func (s *uiStore) Dashboard(context.Context) (delivery.DashboardStats, error) {
	return delivery.DashboardStats{
		ActiveCount:   2,
		ConsumedCount: 7,
		ExpiredCount:  1,
		RevokedCount:  1,
		CreatedToday:  3,
		ConsumedToday: 2,
		RecentActivity: []delivery.ActivityEvent{
			{
				Type:               "secret.created",
				DeliveryID:         testUUID,
				Title:              "Merchant credentials",
				RecipientReference: "merchant-1001",
				Status:             delivery.StatusActive,
				ActorID:            "admin",
				OccurredAt:         time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC),
			},
		},
	}, nil
}

func (s *uiStore) RecentActivity(context.Context, int) ([]delivery.ActivityEvent, error) {
	stats, _ := s.Dashboard(context.Background())
	return stats.RecentActivity, nil
}

func (s *uiStore) Revoke(context.Context, uuid.UUID) (bool, error) {
	return true, nil
}

func (s *uiStore) Prepare(context.Context, []byte) (delivery.PrepareResponse, error) {
	expires := time.Now().UTC().Add(time.Hour)
	return delivery.PrepareResponse{MayAttempt: true, PasswordRequired: false, ExpiresAt: &expires}, nil
}

func (s *uiStore) BeginConsume(context.Context, []byte, uuid.UUID, time.Duration) (delivery.ConsumeCandidate, bool, error) {
	return delivery.ConsumeCandidate{ID: testUUID, EncryptedPayload: "vault:v1:canary"}, true, nil
}

func (s *uiStore) RecordPasswordFailure(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func (s *uiStore) RestoreConsume(context.Context, uuid.UUID, uuid.UUID) error        { return nil }
func (s *uiStore) CompleteConsume(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
	return true, nil
}
func (s *uiStore) CountActive(context.Context) (float64, error) { return 2, nil }

func TestGeneratedHTMLDoesNotContainCreatedSecret(t *testing.T) {
	app := testServer()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secret-links", strings.NewReader(`{"secret":{"password":"canary-secret-value"},"expires_in_seconds":900}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(loginCookie(t, app))
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	raw := rec.Body.String()
	var body map[string]any
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "canary-secret-value") {
		t.Fatal("creation response included plaintext secret")
	}
}
