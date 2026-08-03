package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"secureshare/internal/auth"
	"secureshare/internal/config"
)

var (
	navigationIDPattern     = regexp.MustCompile(`data-nav-item-id="([^"]+)"`)
	activeNavigationPattern = regexp.MustCompile(`data-nav-item-id="([^"]+)"[^>]*aria-current="page"`)
)

func TestNavigationModelUsesRolePermissionsStableOrderAndExplicitActiveRoutes(t *testing.T) {
	cfg := config.Config{SwaggerUIEnabled: true}
	tests := []struct {
		role string
		want []string
	}{
		{role: auth.RoleAdmin, want: []string{"dashboard", "create-secret", "secret-links", "api-clients", "users", "email-settings", "system-status", "api-docs", "help", "account"}},
		{role: auth.RoleDeveloper, want: []string{"dashboard", "create-secret", "secret-links", "api-docs", "help", "account"}},
		{role: auth.RoleViewer, want: []string{"dashboard", "secret-links", "system-status", "api-docs", "help", "account"}},
	}
	for _, test := range tests {
		t.Run(test.role, func(t *testing.T) {
			session := navigationSession(test.role)
			for _, path := range []string{"/admin", "/admin/secrets", "/missing"} {
				if got := navigationItemIDs(buildNavigation(cfg, session, path)); !reflect.DeepEqual(got, test.want) {
					t.Fatalf("%s navigation for %s = %v, want %v", test.role, path, got, test.want)
				}
			}
		})
	}

	activeRoutes := map[string]string{
		"/admin":             "dashboard",
		"/admin/secrets/new": "create-secret",
		"/admin/secrets":     "secret-links",
		"/admin/secrets/11111111-1111-4111-8111-111111111111": "secret-links",
		"/admin/api-clients": "api-clients",
		"/admin/api-clients/11111111-1111-4111-8111-111111111111": "api-clients",
		"/admin/users/11111111-1111-4111-8111-111111111111":       "users",
		"/admin/settings/email":                                   "email-settings",
		"/admin/status":                                           "system-status",
		"/admin/system":                                           "system-status",
		"/docs":                                                   "api-docs",
		"/admin/account":                                          "account",
	}
	for path, want := range activeRoutes {
		if got := activeNavigationID(path); got != want {
			t.Errorf("activeNavigationID(%q) = %q, want %q", path, got, want)
		}
	}
	for _, path := range []string{"/administer", "/admin/secrets-new", "/error", "/missing"} {
		if got := activeNavigationID(path); got != "" {
			t.Errorf("activeNavigationID(%q) = %q, want empty", path, got)
		}
	}
}

func TestRoleNavigationIsIdenticalAcrossProtectedPagesAndErrors(t *testing.T) {
	app, store := testServerWithDeliveryStore(nil)
	createNavigationTestUser(t, app, "developer", auth.RoleDeveloper)
	createNavigationTestUser(t, app, "viewer", auth.RoleViewer)
	adminUser, err := app.users.UserForLogin(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	client, err := auth.CreateAPIClient(context.Background(), app.clients, app.cfg.TokenHMACPepper, auth.APIClientCreate{Name: "Navigation fixture", Scopes: []string{"secret:create"}})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		role     string
		login    string
		password string
		wantIDs  []string
		pages    map[string]string
		blocked  string
	}{
		{
			role: auth.RoleAdmin, login: "admin", password: "change-me-now",
			wantIDs: []string{"dashboard", "create-secret", "secret-links", "api-clients", "users", "email-settings", "system-status", "api-docs", "help", "account"},
			pages: map[string]string{
				"/admin": "dashboard", "/admin/secrets/new": "create-secret", "/admin/secrets": "secret-links",
				"/admin/secrets/" + testUUID.String(): "secret-links", "/admin/api-clients": "api-clients",
				"/admin/api-clients/" + client.ID.String(): "api-clients", "/admin/users": "users",
				"/admin/users/" + adminUser.ID.String(): "users", "/admin/settings/email": "email-settings",
				"/admin/status": "system-status", "/admin/system": "system-status", "/docs": "api-docs",
				"/admin/help": "help", "/admin/account": "account",
			},
		},
		{
			role: auth.RoleDeveloper, login: "developer", password: "developer-passphrase",
			wantIDs: []string{"dashboard", "create-secret", "secret-links", "api-docs", "help", "account"},
			pages: map[string]string{
				"/admin": "dashboard", "/admin/secrets/new": "create-secret", "/admin/secrets": "secret-links",
				"/admin/secrets/" + testUUID.String(): "secret-links", "/docs": "api-docs", "/admin/help": "help", "/admin/account": "account",
			},
			blocked: "/admin/users",
		},
		{
			role: auth.RoleViewer, login: "viewer", password: "viewer-passphrase",
			wantIDs: []string{"dashboard", "secret-links", "system-status", "api-docs", "help", "account"},
			pages: map[string]string{
				"/admin": "dashboard", "/admin/secrets": "secret-links", "/admin/secrets/" + testUUID.String(): "secret-links",
				"/admin/status": "system-status", "/admin/system": "system-status", "/docs": "api-docs",
				"/admin/help": "help", "/admin/account": "account",
			},
			blocked: "/admin/secrets/new",
		},
	}

	for _, test := range tests {
		t.Run(test.role, func(t *testing.T) {
			cookie, _ := loginSession(t, app, test.login, test.password)
			for path, wantActive := range test.pages {
				response := authenticatedPage(t, app, cookie, path)
				if response.Code != http.StatusOK {
					t.Fatalf("GET %s = %d: %s", path, response.Code, response.Body.String())
				}
				assertNavigationHTML(t, response.Body.String(), test.wantIDs, wantActive)
			}

			for _, path := range []string{"/missing-authenticated-page", "/error"} {
				response := authenticatedPage(t, app, cookie, path)
				wantStatus := http.StatusNotFound
				if path == "/error" {
					wantStatus = http.StatusInternalServerError
				}
				if response.Code != wantStatus {
					t.Fatalf("GET %s = %d, want %d", path, response.Code, wantStatus)
				}
				assertNavigationHTML(t, response.Body.String(), test.wantIDs, "")
			}

			if test.blocked != "" {
				response := authenticatedPage(t, app, cookie, test.blocked)
				if response.Code != http.StatusForbidden {
					t.Fatalf("GET %s = %d, want 403", test.blocked, response.Code)
				}
				assertNavigationHTML(t, response.Body.String(), test.wantIDs, "")
				response = authenticatedPage(t, app, cookie, "/admin")
				assertNavigationHTML(t, response.Body.String(), test.wantIDs, "dashboard")
			}
		})
	}

	store.dashboardErr = errors.New("dependency unavailable")
	adminCookie, _ := loginSession(t, app, "admin", "change-me-now")
	response := authenticatedPage(t, app, adminCookie, "/admin")
	assertNavigationHTML(t, response.Body.String(), tests[0].wantIDs, "dashboard")
}

func TestNavigationFeatureAvailabilityAndValidationFailures(t *testing.T) {
	app := testServerWithConfig(func(cfg *config.Config) {
		cfg.SwaggerUIEnabled = false
	})
	cookie, csrf := loginSession(t, app, "admin", "change-me-now")
	response := authenticatedPage(t, app, cookie, "/admin")
	want := []string{"dashboard", "create-secret", "secret-links", "api-clients", "users", "email-settings", "system-status", "help", "account"}
	assertNavigationHTML(t, response.Body.String(), want, "dashboard")
	if strings.Contains(response.Body.String(), `data-nav-item-id="api-docs"`) {
		t.Fatal("API Documentation remained visible when Swagger UI was disabled")
	}
	for _, id := range []string{"create-secret", "email-settings"} {
		if !strings.Contains(response.Body.String(), `data-nav-item-id="`+id+`"`) {
			t.Fatalf("%s disappeared while SMTP is unconfigured", id)
		}
	}

	invalid := httptest.NewRequest(http.MethodPost, "/api/v1/secret-links", strings.NewReader(`{"secret":"validation-canary","expires_in_seconds":691200}`))
	invalid.Header.Set("Content-Type", "application/json")
	invalid.Header.Set("X-CSRF-Token", csrf)
	invalid.AddCookie(cookie)
	invalidResponse := httptest.NewRecorder()
	app.Handler().ServeHTTP(invalidResponse, invalid)
	if invalidResponse.Code == http.StatusCreated {
		t.Fatal("invalid secret form request unexpectedly succeeded")
	}
	response = authenticatedPage(t, app, cookie, "/admin")
	assertNavigationHTML(t, response.Body.String(), want, "dashboard")
}

func TestProtectedPagesUseOneResponsiveShellAndLocalAssets(t *testing.T) {
	app := testServer()
	cookie := loginCookie(t, app)
	for _, path := range []string{"/admin", "/admin/secrets/new", "/admin/secrets", "/admin/account", "/admin/status", "/admin/help", "/docs", "/missing-authenticated-page", "/error"} {
		response := authenticatedPage(t, app, cookie, path)
		body := response.Body.String()
		for marker, want := range map[string]int{
			`id="app-sidebar"`:     1,
			`data-navigation`:      1,
			`data-menu-toggle`:     1,
			`data-nav-backdrop`:    1,
			`id="main-content"`:    1,
			`action="/logout"`:     1,
			`data-user-menu`:       1,
			`href="#main-content"`: 1,
		} {
			if got := strings.Count(body, marker); got != want {
				t.Errorf("GET %s marker %q count = %d, want %d", path, marker, got, want)
			}
		}
		if !strings.Contains(body, `aria-current="page"`) && path != "/missing-authenticated-page" && path != "/error" {
			t.Errorf("GET %s has no accessible active navigation item", path)
		}
	}

	shellBytes, err := os.ReadFile("../../web/templates/_shell.html")
	if err != nil {
		t.Fatal(err)
	}
	shell := string(shellBytes)
	for _, want := range []string{"nav-group", "sidebar-account", "data-menu-close", "data-nav-backdrop", `aria-current="page"`, `role="menu"`, "Skip to main content"} {
		if !strings.Contains(shell, want) {
			t.Errorf("shared shell missing %q", want)
		}
	}
	if strings.Count(shell, `action="/logout"`) != 1 {
		t.Fatal("shared shell must render exactly one logout action")
	}

	cssBytes, err := os.ReadFile("../../web/static/styles.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(cssBytes)
	for _, want := range []string{"--sidebar-width: 252px", "height: 100dvh", "overflow-y: auto", "scrollbar-gutter: stable", "body.navigation-open", ".sidebar.open + .nav-backdrop", "width: min(1520px", "text-overflow: ellipsis"} {
		if !strings.Contains(css, want) {
			t.Errorf("responsive shell CSS missing %q", want)
		}
	}
	for _, asset := range []string{"/static/styles.css", "/static/admin.js", "/static/time.js", "/static/swagger-ui/swagger-ui.css", "/static/swagger-ui/swagger-ui-bundle.js"} {
		response := httptest.NewRecorder()
		app.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, asset, nil))
		if response.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", asset, response.Code)
		}
	}
}

func navigationSession(role string) auth.Session {
	return auth.Session{Role: role, Permissions: permissionsMap(auth.PermissionsForRole(role))}
}

func createNavigationTestUser(t *testing.T, app *Server, username, role string) {
	t.Helper()
	_, err := app.users.CreateUser(context.Background(), auth.UserCreate{
		Username: username, Email: username + "@example.local", Password: username + "-passphrase", Role: role, Status: auth.StatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func authenticatedPage(t *testing.T, app *Server, cookie *http.Cookie, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, request)
	return response
}

func assertNavigationHTML(t *testing.T, body string, wantIDs []string, wantActive string) {
	t.Helper()
	matches := navigationIDPattern.FindAllStringSubmatch(body, -1)
	gotIDs := make([]string, 0, len(matches))
	for _, match := range matches {
		gotIDs = append(gotIDs, match[1])
	}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("navigation IDs = %v, want %v", gotIDs, wantIDs)
	}
	activeMatches := activeNavigationPattern.FindAllStringSubmatch(body, -1)
	if wantActive == "" {
		if len(activeMatches) != 0 {
			t.Fatalf("active navigation = %v, want none", activeMatches)
		}
		return
	}
	if len(activeMatches) != 1 || activeMatches[0][1] != wantActive {
		t.Fatalf("active navigation = %v, want exactly %q", activeMatches, wantActive)
	}
}
