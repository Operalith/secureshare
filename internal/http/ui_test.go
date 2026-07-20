package server

import (
	"bytes"
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
	for _, want := range []string{"SecureShare", "Admin sign in", "Username or email", "data-login-form", "Show"} {
		if !strings.Contains(body, want) {
			t.Fatalf("login page missing %q", want)
		}
	}
}

func TestAdminPagesRendering(t *testing.T) {
	app := testServer()
	cookie := loginCookie(t, app)
	client, err := auth.CreateAPIClient(context.Background(), app.clients, app.cfg.TokenHMACPepper, auth.APIClientCreate{
		Name:   "Render test client",
		Scopes: []string{"secret:create"},
	})
	if err != nil {
		t.Fatalf("create api client fixture: %v", err)
	}
	for _, path := range []string{"/admin", "/admin/secrets/new", "/admin/secrets", "/admin/secrets/" + testUUID.String(), "/admin/users", "/admin/users/new", "/admin/api-clients", "/admin/api-clients/new", "/admin/api-clients/" + client.ID.String(), "/admin/account", "/admin/status", "/admin/help", "/docs"} {
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
	for _, path := range []string{
		"../../web/templates/login.html",
		"../../web/templates/admin.html",
		"../../web/templates/new_secret.html",
		"../../web/templates/secret_list.html",
		"../../web/templates/secret_detail.html",
		"../../web/templates/recipient.html",
		"../../web/templates/users.html",
		"../../web/templates/user_new.html",
		"../../web/templates/user_detail.html",
		"../../web/templates/api_clients.html",
		"../../web/templates/api_client_new.html",
		"../../web/templates/api_client_detail.html",
		"../../web/templates/account.html",
		"../../web/templates/status.html",
		"../../web/templates/help.html",
		"../../web/templates/error.html",
		"../../web/static/admin.js",
		"../../web/static/reveal.js",
	} {
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
		"Content-Security-Policy": "font-src 'self'",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
	} {
		if got := headers.Get(key); !strings.Contains(got, want) {
			t.Fatalf("%s = %q, want contains %q", key, got, want)
		}
	}
}

func TestBrowserLogoutRedirectsClearsCookieAndRevokesSession(t *testing.T) {
	app := testServer()
	cookie, csrf := loginSession(t, app, "admin", "change-me-now")
	req := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader("csrf_token="+csrf))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("browser logout status = %d, want 303: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/login" {
		t.Fatalf("browser logout location = %q, want /login", got)
	}
	deleted := false
	for _, out := range rec.Result().Cookies() {
		if out.Name == auth.CookieName && out.MaxAge < 0 {
			deleted = true
		}
	}
	if !deleted {
		t.Fatal("browser logout did not delete the session cookie")
	}

	adminReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	adminReq.AddCookie(cookie)
	adminRec := httptest.NewRecorder()
	app.Handler().ServeHTTP(adminRec, adminReq)
	if adminRec.Code != http.StatusFound || adminRec.Header().Get("Location") != "/login" {
		t.Fatalf("revoked session admin access = %d location=%q", adminRec.Code, adminRec.Header().Get("Location"))
	}
}

func TestBrowserLogoutRequiresPOSTAndCSRF(t *testing.T) {
	app := testServer()
	cookie := loginCookie(t, app)
	for _, path := range []string{"/logout", "/api/v1/auth/logout"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		app.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s = %d, want 405", path, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("browser logout without CSRF = %d, want 403", rec.Code)
	}
}

func TestAuthenticationPageRedirects(t *testing.T) {
	app := testServer()
	unauth := httptest.NewRecorder()
	app.Handler().ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if unauth.Code != http.StatusFound || unauth.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated admin = %d location=%q", unauth.Code, unauth.Header().Get("Location"))
	}

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.AddCookie(loginCookie(t, app))
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin" {
		t.Fatalf("authenticated login page = %d location=%q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestDisabledAndExpiredSessionsLosePageAccess(t *testing.T) {
	app := testServerWithConfig(func(cfg *config.Config) {
		cfg.SessionTTL = 15 * time.Millisecond
		cfg.SessionIdleTimeout = 10 * time.Millisecond
	})
	cookie, _ := loginSession(t, app, "admin", "change-me-now")
	user, err := app.users.UserForLogin(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.users.SetUserStatus(context.Background(), user.ID, auth.StatusDisabled); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login" {
		t.Fatalf("disabled user page access = %d location=%q", rec.Code, rec.Header().Get("Location"))
	}

	if _, err := app.users.SetUserStatus(context.Background(), user.ID, auth.StatusActive); err != nil {
		t.Fatal(err)
	}
	expiringCookie, _ := loginSession(t, app, "admin", "change-me-now")
	time.Sleep(25 * time.Millisecond)
	expiredReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	expiredReq.AddCookie(expiringCookie)
	expiredRec := httptest.NewRecorder()
	app.Handler().ServeHTTP(expiredRec, expiredReq)
	if expiredRec.Code != http.StatusFound || expiredRec.Header().Get("Location") != "/login" {
		t.Fatalf("expired user page access = %d location=%q", expiredRec.Code, expiredRec.Header().Get("Location"))
	}
}

func TestTypographyUsesLocalFontPolicyAndLTRTechnicalValues(t *testing.T) {
	cssBytes, err := os.ReadFile("../../web/static/styles.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(cssBytes)
	for _, want := range []string{
		`--font-sans: -apple-system`,
		`--font-persian:`,
		`--font-mono: ui-monospace`,
		"direction: ltr",
		"unicode-bidi: isolate",
		"[dir=\"rtl\"]",
		":lang(fa)",
	} {
		if !strings.Contains(css, want) {
			t.Fatalf("styles.css missing typography rule %q", want)
		}
	}
	for _, forbidden := range []string{"url(http://", "url(https://", "fonts.googleapis", "fonts.gstatic"} {
		if strings.Contains(css, forbidden) {
			t.Fatalf("styles.css contains external font reference %q", forbidden)
		}
	}
	if _, err := os.Stat("../../web/static/fonts/README.md"); err != nil {
		t.Fatalf("local fonts directory documentation missing: %v", err)
	}
	app := testServer()
	for _, path := range []string{"/static/styles.css", "/static/admin.js", "/static/reveal.js"} {
		rec := httptest.NewRecorder()
		app.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", path, rec.Code)
		}
	}
	for _, path := range []string{"../../web/templates/new_secret.html", "../../web/templates/secret_detail.html", "../../web/templates/account.html", "../../web/static/reveal.js"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "technical-value") {
			t.Fatalf("%s missing technical-value marker", path)
		}
	}
}

func TestOpenAPISpecDocumentsRequiredRoutesAndSchemas(t *testing.T) {
	rawBytes, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	raw := string(rawBytes)
	for _, want := range []string{
		"openapi: 3.1.0",
		"/api/v1/secret-links:",
		"/api/v1/secret-links/{id}:",
		"/api/v1/secret-links/consume:",
		"/api/v1/api-clients:",
		"/api/v1/users:",
		"StructuredSecretPayload:",
		"StructuredSecretField:",
		"TextSecretPayload:",
		"JSONSecretPayload:",
		"CreateSecretRequest:",
		"CreateSecretResponse:",
		"SecretMetadata:",
		"SecretListResponse:",
		"Pagination:",
		"ErrorResponse:",
		"DashboardResponse:",
		"CurrentUser:",
		"APIClient:",
		"CreateAPIClientRequest:",
		"CreateAPIClientResponse:",
		"scheme: basic",
		"writeOnly: true",
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("openapi.yaml missing %q", want)
		}
	}
	for _, forbidden := range []string{"sk_live_", "real-secret", "production-secret"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("openapi.yaml contains forbidden realistic secret example %q", forbidden)
		}
	}
}

func TestSwaggerUIRoutesAccessControlAndLocalAssets(t *testing.T) {
	app := testServer()
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/docs", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("unauthenticated docs = %d, want 302", rec.Code)
	}

	specRec := httptest.NewRecorder()
	app.Handler().ServeHTTP(specRec, httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil))
	if specRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated openapi = %d, want 401", specRec.Code)
	}

	cookie := loginCookie(t, app)
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated docs = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"/static/swagger-ui/swagger-ui.css", "/static/swagger-ui/swagger-ui-bundle.js", "/static/swagger-ui/swagger-init.js", "/openapi.yaml"} {
		if !strings.Contains(body, want) {
			t.Fatalf("docs page missing local asset %q", want)
		}
	}
	if strings.Contains(body, "https://cdn") || strings.Contains(body, "persistAuthorization: true") {
		t.Fatalf("docs page contains external CDN or persisted auth config")
	}

	initBytes, err := os.ReadFile("../../web/static/swagger-ui/swagger-init.js")
	if err != nil {
		t.Fatal(err)
	}
	init := string(initBytes)
	for _, want := range []string{"persistAuthorization: false", "validatorUrl: null"} {
		if !strings.Contains(init, want) {
			t.Fatalf("swagger init missing %q", want)
		}
	}
	for _, forbidden := range []string{"localStorage", "sessionStorage", "indexedDB"} {
		if strings.Contains(init, forbidden) {
			t.Fatalf("swagger init contains browser storage reference %q", forbidden)
		}
	}

	specReq := httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil)
	specReq.AddCookie(cookie)
	specRec = httptest.NewRecorder()
	app.Handler().ServeHTTP(specRec, specReq)
	if specRec.Code != http.StatusOK {
		t.Fatalf("authenticated openapi = %d, want 200", specRec.Code)
	}
	if !strings.Contains(specRec.Body.String(), "openapi: 3.1.0") {
		t.Fatal("served openapi spec missing version")
	}
}

func TestOpenAPIPublicModeDoesNotRenderAdminIdentity(t *testing.T) {
	app := testServerWithConfig(func(cfg *config.Config) {
		cfg.OpenAPIPublic = true
	})
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/docs", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("public docs = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "Logout") || strings.Contains(rec.Body.String(), "user-pill\">admin") {
		t.Fatalf("public docs rendered authenticated admin chrome: %s", rec.Body.String())
	}

	specRec := httptest.NewRecorder()
	app.Handler().ServeHTTP(specRec, httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil))
	if specRec.Code != http.StatusOK {
		t.Fatalf("public openapi = %d, want 200", specRec.Code)
	}
}

func TestDeveloperExamplesAndPostmanArtifacts(t *testing.T) {
	for _, path := range []string{
		"../../docs/DEVELOPER_GUIDE.md",
		"../../examples/curl/README.md",
		"../../examples/go/main.go",
		"../../examples/python/create_secret.py",
		"../../examples/javascript/create-secret.mjs",
		"../../docs/postman/secureshare.postman_collection.json",
		"../../docs/postman/secureshare.local.postman_environment.json",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		for _, want := range []string{"SECURESHARE_CLIENT_ID", "SECURESHARE_CLIENT_SECRET"} {
			if (strings.Contains(path, "examples/") || strings.Contains(path, "DEVELOPER_GUIDE")) && !strings.Contains(text, want) {
				t.Fatalf("%s missing environment credential %q", path, want)
			}
		}
		for _, forbidden := range []string{"sk_live_", "real-secret", "production-secret"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains forbidden realistic secret example %q", path, forbidden)
			}
		}
	}

	for _, path := range []string{
		"../../docs/postman/secureshare.postman_collection.json",
		"../../docs/postman/secureshare.local.postman_environment.json",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var parsed map[string]any
		if err := json.Unmarshal(raw, &parsed); err != nil {
			t.Fatalf("%s is not valid JSON: %v", path, err)
		}
	}
}

func loginCookie(t *testing.T, app *Server) *http.Cookie {
	t.Helper()
	cookie, _ := loginSession(t, app, "admin", "change-me-now")
	return cookie
}

func loginSession(t *testing.T, app *Server, login, password string) (*http.Cookie, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"login":"`+login+`","password":"`+password+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	csrfToken, _ := body["csrf_token"].(string)
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == auth.CookieName {
			return cookie, csrfToken
		}
	}
	t.Fatal("login did not set session cookie")
	return nil, ""
}

func testServer() *Server {
	return testServerWithConfig(nil)
}

func testServerWithConfig(configure func(*config.Config)) *Server {
	cfg := config.Config{
		AppEnv:                   "development",
		AppVersion:               "test",
		AppBaseURL:               "http://localhost:8080",
		AdminAPIKey:              "change-me",
		LegacyAdminAPIKeyEnabled: true,
		SwaggerUIEnabled:         true,
		TokenHMACPepper:          "test-pepper-with-enough-length",
		SessionSecret:            "test-session-secret-with-enough-length",
		CSRFSecret:               "test-csrf-secret-with-enough-length",
		SessionTTL:               time.Hour,
		SessionIdleTimeout:       30 * time.Minute,
		RequestIPHashPepper:      "ip-pepper-with-enough-length",
		MaxSecretTTL:             7 * 24 * time.Hour,
		DefaultSecretTTL:         24 * time.Hour,
		ConsumingLeaseTTL:        30 * time.Second,
		MaxSecretBytes:           config.DefaultMaxSecretBytes,
	}
	if configure != nil {
		configure(&cfg)
	}
	users := auth.NewMemoryStore()
	if _, err := users.CreateUser(context.Background(), auth.UserCreate{
		Username: "admin",
		Email:    "admin@example.local",
		Password: "change-me-now",
		Role:     auth.RoleAdmin,
		Status:   auth.StatusActive,
	}); err != nil {
		panic(err)
	}
	return New(Dependencies{
		Config:   cfg,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Auth:     auth.NewSessionManager(cfg.SessionSecret, cfg.CSRFSecret, cfg.SessionTTL, cfg.SessionIdleTimeout, false).WithStore(users),
		Delivery: delivery.NewService(cfg, &uiStore{}, &uiVault{}, observability.New(), slog.Default()),
		Metrics:  observability.New(),
		Limits:   ratelimit.NewRegistry(),
		Users:    users,
		Clients:  users,
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
		PayloadType:        "structured",
		PayloadFieldCount:  3,
		ContainsSensitive:  true,
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

func (s *uiStore) Revoke(context.Context, uuid.UUID) (delivery.RevokeResult, error) {
	return delivery.RevokeResult{ID: testUUID, Status: delivery.StatusRevoked, Revoked: true, Found: true}, nil
}

func (s *uiStore) RecordAuditEvent(context.Context, delivery.AuditEventRecord) error { return nil }

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
func (s *uiStore) Cleanup(context.Context, time.Duration, time.Duration, time.Duration, time.Duration, time.Duration) (delivery.CleanupResult, error) {
	return delivery.CleanupResult{}, nil
}
func (s *uiStore) CountActive(context.Context) (float64, error) { return 2, nil }

func TestGeneratedHTMLDoesNotContainCreatedSecret(t *testing.T) {
	app := testServer()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secret-links", strings.NewReader(`{"secret":{"password":"canary-secret-value"},"expires_in_seconds":900}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer change-me")
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

func TestCSRFRejectsSessionStateChangeWithoutToken(t *testing.T) {
	app := testServer()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secret-links", strings.NewReader(`{"secret":"blocked","expires_in_seconds":900}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(loginCookie(t, app))
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("session create without CSRF = %d, want 403", rec.Code)
	}
}

func TestBearerCreateBypassesBrowserCSRF(t *testing.T) {
	app := testServer()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secret-links", strings.NewReader(`{"secret":"ok","expires_in_seconds":900}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer change-me")
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("bearer create = %d, want 201: %s", rec.Code, rec.Body.String())
	}
}

func TestInvalidJSONContentTypeRejected(t *testing.T) {
	app := testServer()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secret-links", strings.NewReader(`{"secret":"ok","expires_in_seconds":900}`))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Authorization", "Bearer change-me")
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("invalid content type = %d, want 415", rec.Code)
	}
}

func TestCurrentUserAndViewerRoleEnforcement(t *testing.T) {
	app := testServer()
	cookie, csrf := loginSession(t, app, "admin", "change-me-now")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("me status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"role":"admin"`) {
		t.Fatalf("current user response missing admin role: %s", rec.Body.String())
	}

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"username":"viewer1","email":"viewer1@example.local","password":"viewer passphrase","role":"viewer"}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("X-CSRF-Token", csrf)
	createReq.AddCookie(cookie)
	createRec := httptest.NewRecorder()
	app.Handler().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create viewer = %d, want 201: %s", createRec.Code, createRec.Body.String())
	}

	viewerCookie, viewerCSRF := loginSession(t, app, "viewer1", "viewer passphrase")
	blocked := httptest.NewRequest(http.MethodPost, "/api/v1/secret-links", strings.NewReader(`{"secret":"blocked","expires_in_seconds":900}`))
	blocked.Header.Set("Content-Type", "application/json")
	blocked.Header.Set("X-CSRF-Token", viewerCSRF)
	blocked.AddCookie(viewerCookie)
	blockedRec := httptest.NewRecorder()
	app.Handler().ServeHTTP(blockedRec, blocked)
	if blockedRec.Code != http.StatusUnauthorized {
		t.Fatalf("viewer create = %d, want 401", blockedRec.Code)
	}
}

func TestUserManagementDisableAndPasswordReset(t *testing.T) {
	app := testServer()
	cookie, csrf := loginSession(t, app, "admin", "change-me-now")
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"username":"developer1","email":"developer1@example.local","password":"developer passphrase","role":"developer"}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("X-CSRF-Token", csrf)
	createReq.AddCookie(cookie)
	createRec := httptest.NewRecorder()
	app.Handler().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create developer = %d, want 201: %s", createRec.Code, createRec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	disableReq := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+created.ID+"/disable", strings.NewReader(`{}`))
	disableReq.Header.Set("Content-Type", "application/json")
	disableReq.Header.Set("X-CSRF-Token", csrf)
	disableReq.AddCookie(cookie)
	disableRec := httptest.NewRecorder()
	app.Handler().ServeHTTP(disableRec, disableReq)
	if disableRec.Code != http.StatusOK {
		t.Fatalf("disable developer = %d, want 200: %s", disableRec.Code, disableRec.Body.String())
	}
	badLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"login":"developer1","password":"developer passphrase"}`))
	badLogin.Header.Set("Content-Type", "application/json")
	badRec := httptest.NewRecorder()
	app.Handler().ServeHTTP(badRec, badLogin)
	if badRec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled login = %d, want 401", badRec.Code)
	}

	enableReq := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+created.ID+"/enable", strings.NewReader(`{}`))
	enableReq.Header.Set("Content-Type", "application/json")
	enableReq.Header.Set("X-CSRF-Token", csrf)
	enableReq.AddCookie(cookie)
	app.Handler().ServeHTTP(httptest.NewRecorder(), enableReq)
	resetReq := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+created.ID+"/reset-password", strings.NewReader(`{"password":"new developer passphrase"}`))
	resetReq.Header.Set("Content-Type", "application/json")
	resetReq.Header.Set("X-CSRF-Token", csrf)
	resetReq.AddCookie(cookie)
	resetRec := httptest.NewRecorder()
	app.Handler().ServeHTTP(resetRec, resetReq)
	if resetRec.Code != http.StatusOK {
		t.Fatalf("reset password = %d, want 200: %s", resetRec.Code, resetRec.Body.String())
	}
	loginSession(t, app, "developer1", "new developer passphrase")
}

func TestAPIClientManagementShowsSecretOnlyOnce(t *testing.T) {
	app := testServer()
	cookie, csrf := loginSession(t, app, "admin", "change-me-now")
	created, raw := createAPIClientViaHTTP(t, app, cookie, csrf, "One-time display client", []string{"secret:create"}, "")
	if created.ClientSecret == "" {
		t.Fatal("create response did not include one-time client secret")
	}
	if !strings.Contains(raw, created.ClientSecret) {
		t.Fatal("create response did not contain the generated client secret")
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/api-clients", nil)
	listReq.AddCookie(cookie)
	listRec := httptest.NewRecorder()
	app.Handler().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list api clients = %d, want 200: %s", listRec.Code, listRec.Body.String())
	}
	if strings.Contains(listRec.Body.String(), created.ClientSecret) || strings.Contains(listRec.Body.String(), "client_secret") || strings.Contains(listRec.Body.String(), "client_secret_hash") {
		t.Fatalf("list response leaked client secret material: %s", listRec.Body.String())
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/api/v1/api-clients/"+created.ID.String(), nil)
	detailReq.AddCookie(cookie)
	detailRec := httptest.NewRecorder()
	app.Handler().ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("get api client = %d, want 200: %s", detailRec.Code, detailRec.Body.String())
	}
	if strings.Contains(detailRec.Body.String(), created.ClientSecret) || strings.Contains(detailRec.Body.String(), "client_secret") || strings.Contains(detailRec.Body.String(), "client_secret_hash") {
		t.Fatalf("detail response leaked client secret material: %s", detailRec.Body.String())
	}
}

func TestAPIClientBasicAuthScopesRotationAndRevocation(t *testing.T) {
	app := testServer()
	cookie, csrf := loginSession(t, app, "admin", "change-me-now")
	created, _ := createAPIClientViaHTTP(t, app, cookie, csrf, "Scoped creator", []string{"secret:create"}, "")

	createStatus := createSecretWithBasic(t, app, created.ClientID, created.ClientSecret, "basic-auth-secret")
	if createStatus != http.StatusCreated {
		t.Fatalf("basic-auth create = %d, want 201", createStatus)
	}
	if got := createSecretWithBasic(t, app, created.ClientID, "wrong-secret", "wrong-secret-payload"); got != http.StatusUnauthorized {
		t.Fatalf("invalid basic auth = %d, want 401", got)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/secret-links", nil)
	listReq.SetBasicAuth(created.ClientID, created.ClientSecret)
	listRec := httptest.NewRecorder()
	app.Handler().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusUnauthorized {
		t.Fatalf("client without read scope listed secrets: status=%d body=%s", listRec.Code, listRec.Body.String())
	}

	actionStatus := apiClientAction(t, app, cookie, csrf, created.ID.String(), "disable")
	if actionStatus != http.StatusOK {
		t.Fatalf("disable api client = %d, want 200", actionStatus)
	}
	if got := createSecretWithBasic(t, app, created.ClientID, created.ClientSecret, "disabled-secret"); got != http.StatusUnauthorized {
		t.Fatalf("disabled client create = %d, want 401", got)
	}

	rotated := rotateAPIClient(t, app, cookie, csrf, created.ID.String())
	if rotated.ClientSecret == "" || rotated.ClientSecret == created.ClientSecret {
		t.Fatal("rotation did not return a new one-time secret")
	}
	if got := createSecretWithBasic(t, app, created.ClientID, created.ClientSecret, "old-rotated-secret"); got != http.StatusUnauthorized {
		t.Fatalf("old rotated client secret = %d, want 401", got)
	}
	if got := createSecretWithBasic(t, app, rotated.ClientID, rotated.ClientSecret, "new-rotated-secret"); got != http.StatusCreated {
		t.Fatalf("new rotated client secret = %d, want 201", got)
	}

	actionStatus = apiClientAction(t, app, cookie, csrf, created.ID.String(), "revoke")
	if actionStatus != http.StatusOK {
		t.Fatalf("revoke api client = %d, want 200", actionStatus)
	}
	if got := createSecretWithBasic(t, app, rotated.ClientID, rotated.ClientSecret, "revoked-secret"); got != http.StatusUnauthorized {
		t.Fatalf("revoked client create = %d, want 401", got)
	}
}

func TestExpiredAPIClientRejected(t *testing.T) {
	app := testServer()
	cookie, csrf := loginSession(t, app, "admin", "change-me-now")
	expired := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	created, _ := createAPIClientViaHTTP(t, app, cookie, csrf, "Expired client", []string{"secret:create"}, expired)
	if got := createSecretWithBasic(t, app, created.ClientID, created.ClientSecret, "expired-client-secret"); got != http.StatusUnauthorized {
		t.Fatalf("expired client create = %d, want 401", got)
	}
}

func TestLegacyAPIKeyDisabledMode(t *testing.T) {
	app := testServerWithConfig(func(cfg *config.Config) {
		cfg.LegacyAdminAPIKeyEnabled = false
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secret-links", strings.NewReader(`{"secret":"blocked","expires_in_seconds":900}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer change-me")
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("legacy bearer with disabled mode = %d, want 401", rec.Code)
	}
}

func createAPIClientViaHTTP(t *testing.T, app *Server, cookie *http.Cookie, csrf, name string, scopes []string, expiresAt string) (auth.APIClientCreateResult, string) {
	t.Helper()
	payload := map[string]any{
		"name":       name,
		"scopes":     scopes,
		"expires_at": expiresAt,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-clients", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create api client = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var created auth.APIClientCreateResult
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	return created, rec.Body.String()
}

func rotateAPIClient(t *testing.T, app *Server, cookie *http.Cookie, csrf, id string) auth.APIClientCreateResult {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-clients/"+id+"/rotate-secret", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate api client = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var rotated auth.APIClientCreateResult
	if err := json.Unmarshal(rec.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	return rotated
}

func apiClientAction(t *testing.T, app *Server, cookie *http.Cookie, csrf, id, action string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-clients/"+id+"/"+action, nil)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	return rec.Code
}

func createSecretWithBasic(t *testing.T, app *Server, clientID, clientSecret, value string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secret-links", strings.NewReader(`{"secret":"`+value+`","expires_in_seconds":900}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(clientID, clientSecret)
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	return rec.Code
}
