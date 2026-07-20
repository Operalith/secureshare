package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"secureshare/internal/auth"
	"secureshare/internal/config"
	securecrypto "secureshare/internal/crypto"
	"secureshare/internal/delivery"
	secureemail "secureshare/internal/email"
	"secureshare/internal/middleware"
	"secureshare/internal/observability"
	"secureshare/internal/ratelimit"
)

type Dependencies struct {
	Config   config.Config
	Logger   *slog.Logger
	Auth     *auth.SessionManager
	Delivery *delivery.Service
	Email    *secureemail.Service
	DB       *pgxpool.Pool
	Vault    delivery.Vault
	Metrics  *observability.Metrics
	Limits   *ratelimit.Registry
	Users    auth.UserStore
	Clients  auth.APIClientStore
}

type Server struct {
	cfg       config.Config
	logger    *slog.Logger
	auth      *auth.SessionManager
	delivery  *delivery.Service
	email     *secureemail.Service
	db        *pgxpool.Pool
	vault     delivery.Vault
	metrics   *observability.Metrics
	limits    *ratelimit.Registry
	users     auth.UserStore
	clients   auth.APIClientStore
	templates *template.Template
}

func New(deps Dependencies) *Server {
	funcs := template.FuncMap{
		"formatTime": func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
		"formatOptionalTime": func(t *time.Time) string {
			if t == nil {
				return "Not recorded"
			}
			return t.UTC().Format(time.RFC3339)
		},
		"statusClass": statusClass,
		"eventLabel":  eventLabel,
		"hasPermission": func(perms map[string]bool, permission string) bool {
			return perms[permission]
		},
		"shortID": func(id uuid.UUID) string {
			value := id.String()
			if len(value) <= 8 {
				return value
			}
			return value[:8]
		},
	}
	templates := template.Must(template.New("").Funcs(funcs).ParseGlob(templatePattern()))
	return &Server{
		cfg:       deps.Config,
		logger:    deps.Logger,
		auth:      deps.Auth,
		delivery:  deps.Delivery,
		email:     deps.Email,
		db:        deps.DB,
		vault:     deps.Vault,
		metrics:   deps.Metrics,
		limits:    deps.Limits,
		users:     deps.Users,
		clients:   deps.Clients,
		templates: templates,
	}
}

func templatePattern() string {
	pattern := filepath.Join("web", "templates", "*.html")
	if matches, _ := filepath.Glob(pattern); len(matches) > 0 {
		return pattern
	}
	return filepath.Join("..", "..", "web", "templates", "*.html")
}

func staticDir() string {
	path := filepath.Join("web", "static")
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return filepath.Join("..", "..", "web", "static")
}

func openAPIPath() string {
	path := filepath.Join("docs", "openapi.yaml")
	if matches, _ := filepath.Glob(path); len(matches) > 0 {
		return path
	}
	return filepath.Join("..", "..", "docs", "openapi.yaml")
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir()))))
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/docs", s.handleDocsPage)
	mux.HandleFunc("/openapi.yaml", s.handleOpenAPISpec)
	mux.HandleFunc("/login", s.handleLoginPage)
	mux.HandleFunc("/logout", s.handleBrowserLogout)
	mux.HandleFunc("/admin", s.handleAdmin)
	mux.HandleFunc("/admin/secrets", s.handleSecretListPage)
	mux.HandleFunc("/admin/secrets/new", s.handleNewSecretPage)
	mux.HandleFunc("/admin/secrets/", s.handleSecretPage)
	mux.HandleFunc("/admin/status", s.handleStatusPage)
	mux.HandleFunc("/admin/help", s.handleHelpPage)
	mux.HandleFunc("/admin/users", s.handleUsersPage)
	mux.HandleFunc("/admin/users/new", s.handleNewUserPage)
	mux.HandleFunc("/admin/users/", s.handleUserDetailPage)
	mux.HandleFunc("/admin/account", s.handleAccountPage)
	mux.HandleFunc("/admin/settings/email", s.handleEmailSettingsPage)
	mux.HandleFunc("/admin/api-clients", s.handleAPIClientsPage)
	mux.HandleFunc("/admin/api-clients/new", s.handleNewAPIClientPage)
	mux.HandleFunc("/admin/api-clients/", s.handleAPIClientDetailPage)
	mux.HandleFunc("/s", s.handleRecipientPage)
	mux.HandleFunc("/error", s.handleErrorPage)
	mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("/api/v1/auth/logout", s.handleLogout)
	mux.HandleFunc("/api/v1/me", s.handleMe)
	mux.HandleFunc("/api/v1/me/password", s.handleChangePassword)
	mux.HandleFunc("/api/v1/me/sessions", s.handleMySessions)
	mux.HandleFunc("/api/v1/me/sessions/revoke-other", s.handleRevokeOtherSessions)
	mux.HandleFunc("/api/v1/dashboard", s.handleDashboardAPI)
	mux.HandleFunc("/api/v1/admin/cleanup", s.handleManualCleanup)
	mux.HandleFunc("/api/v1/settings/email", s.handleEmailSettingsAPI)
	mux.HandleFunc("/api/v1/settings/email/", s.handleEmailSettingsActionAPI)
	mux.HandleFunc("/api/v1/users", s.handleUsersAPI)
	mux.HandleFunc("/api/v1/users/", s.handleUserAPI)
	mux.HandleFunc("/api/v1/api-clients", s.handleAPIClientsAPI)
	mux.HandleFunc("/api/v1/api-clients/", s.handleAPIClientAPI)
	mux.HandleFunc("/api/v1/secret-links", s.handleSecretLinks)
	mux.HandleFunc("/api/v1/secret-links/", s.handleSecretLinkByID)
	mux.HandleFunc("/api/v1/secret-links/prepare", s.handlePrepare)
	mux.HandleFunc("/api/v1/secret-links/consume", s.handleConsume)
	mux.HandleFunc("/health/live", s.handleLive)
	mux.HandleFunc("/health/ready", s.handleReady)
	if s.cfg.MetricsEnabled {
		mux.Handle("/metrics", s.metrics.Handler())
	}

	var handler http.Handler = mux
	handler = middleware.SecurityHeaders(s.cfg, handler)
	handler = middleware.Logging(s.logger, s.cfg, handler)
	return handler
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.auth.FromRequest(r); ok {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	s.render(w, "login.html", map[string]any{"Title": "Login", "Env": s.cfg.AppEnv})
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin" {
		http.NotFound(w, r)
		return
	}
	if !s.requirePage(w, r, "dashboard:read") {
		return
	}
	stats, err := s.delivery.Dashboard(r.Context())
	if err != nil {
		s.logger.Warn("dashboard query failed", "error", err)
	}
	stats.Dependencies = s.dependencyState(r.Context())
	s.render(w, "admin.html", s.adminData(r, map[string]any{
		"Title": "Dashboard",
		"Stats": stats,
	}))
}

func (s *Server) handleNewSecretPage(w http.ResponseWriter, r *http.Request) {
	if !s.requirePage(w, r, "secret:create") {
		return
	}
	s.render(w, "new_secret.html", s.adminData(r, map[string]any{"Title": "Create Secret", "MaxTTLHours": int(s.cfg.MaxSecretTTL.Hours())}))
}

func (s *Server) handleSecretListPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin/secrets" {
		http.NotFound(w, r)
		return
	}
	if !s.requirePage(w, r, "secret:read-metadata") {
		return
	}
	opts := parseListOptions(r)
	result, err := s.delivery.List(r.Context(), opts)
	if err != nil {
		s.logger.Warn("secret list query failed", "error", err)
	}
	s.render(w, "secret_list.html", s.adminData(r, map[string]any{
		"Title":       "Secret Links",
		"Result":      result,
		"Filters":     opts,
		"PrevURL":     pageURL(r, result.Pagination.Page-1),
		"NextURL":     pageURL(r, result.Pagination.Page+1),
		"CanPrevious": result.Pagination.Page > 1,
		"CanNext":     result.Pagination.TotalPages > 0 && result.Pagination.Page < result.Pagination.TotalPages,
	}))
}

func (s *Server) handleSecretPage(w http.ResponseWriter, r *http.Request) {
	if !s.requirePage(w, r, "secret:read-metadata") {
		return
	}
	idText := strings.TrimPrefix(r.URL.Path, "/admin/secrets/")
	id, err := uuid.Parse(idText)
	if err != nil {
		s.render(w, "error.html", map[string]any{"Title": "Unavailable", "Message": "Secret metadata is unavailable."})
		return
	}
	meta, err := s.delivery.Metadata(r.Context(), id)
	if err != nil {
		s.render(w, "error.html", map[string]any{"Title": "Unavailable", "Message": "Secret metadata is unavailable."})
		return
	}
	events, err := s.delivery.RecentActivity(r.Context(), 20)
	if err != nil {
		s.logger.Warn("timeline query failed", "delivery_id", id, "error", err)
	}
	timeline := []delivery.ActivityEvent{}
	for _, event := range events {
		if event.DeliveryID == id {
			timeline = append(timeline, event)
		}
	}
	s.render(w, "secret_detail.html", s.adminData(r, map[string]any{"Title": "Secret Metadata", "Secret": meta, "Timeline": timeline}))
}

func (s *Server) handleStatusPage(w http.ResponseWriter, r *http.Request) {
	if !s.requirePage(w, r, "system:read") {
		return
	}
	stats, err := s.delivery.Dashboard(r.Context())
	if err != nil {
		s.logger.Warn("status dashboard query failed", "error", err)
	}
	stats.Dependencies = s.dependencyState(r.Context())
	s.render(w, "status.html", s.adminData(r, map[string]any{"Title": "System Status", "Stats": stats}))
}

func (s *Server) handleHelpPage(w http.ResponseWriter, r *http.Request) {
	if !s.requirePage(w, r, "api-docs:read") {
		return
	}
	s.render(w, "help.html", s.adminData(r, map[string]any{"Title": "Help"}))
}

func (s *Server) handleDocsPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/docs" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	if !s.cfg.SwaggerUIEnabled {
		http.NotFound(w, r)
		return
	}
	if !s.requireDocsAccess(w, r, true) {
		return
	}
	data := map[string]any{
		"Title":         "API Docs",
		"Env":           s.cfg.AppEnv,
		"ActorID":       "public",
		"Role":          "public",
		"Permissions":   permissionsMap([]string{"api-docs:read"}),
		"OpenAPIPublic": s.cfg.OpenAPIPublic,
	}
	if _, ok := s.auth.FromRequest(r); ok {
		data = s.adminData(r, map[string]any{"Title": "API Docs", "OpenAPIPublic": s.cfg.OpenAPIPublic})
	}
	s.render(w, "docs.html", data)
}

func (s *Server) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireDocsAccess(w, r, false) {
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	http.ServeFile(w, r, openAPIPath())
}

func (s *Server) requireDocsAccess(w http.ResponseWriter, r *http.Request, browserPage bool) bool {
	if s.cfg.OpenAPIPublic {
		return true
	}
	if session, ok := s.auth.FromRequest(r); ok && session.Permissions["api-docs:read"] {
		return true
	}
	if browserPage {
		http.Redirect(w, r, "/login", http.StatusFound)
		return false
	}
	s.writeError(w, delivery.CodeUnauthorized, "Unauthorized.", http.StatusUnauthorized)
	return false
}

func (s *Server) handleUsersPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin/users" {
		http.NotFound(w, r)
		return
	}
	if !s.requirePage(w, r, "user:manage") {
		return
	}
	users, err := s.users.ListUsers(r.Context())
	if err != nil {
		s.logger.Warn("user list query failed", "error", err)
	}
	s.render(w, "users.html", s.adminData(r, map[string]any{"Title": "Users", "Users": users}))
}

func (s *Server) handleNewUserPage(w http.ResponseWriter, r *http.Request) {
	if !s.requirePage(w, r, "user:manage") {
		return
	}
	s.render(w, "user_new.html", s.adminData(r, map[string]any{"Title": "Create User"}))
}

func (s *Server) handleUserDetailPage(w http.ResponseWriter, r *http.Request) {
	if !s.requirePage(w, r, "user:manage") {
		return
	}
	id, err := uuid.Parse(strings.TrimPrefix(r.URL.Path, "/admin/users/"))
	if err != nil {
		s.render(w, "error.html", map[string]any{"Title": "Unavailable", "Message": "User metadata is unavailable."})
		return
	}
	user, err := s.users.UserByID(r.Context(), id)
	if err != nil {
		s.render(w, "error.html", map[string]any{"Title": "Unavailable", "Message": "User metadata is unavailable."})
		return
	}
	s.render(w, "user_detail.html", s.adminData(r, map[string]any{"Title": "User Detail", "User": user}))
}

func (s *Server) handleAccountPage(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requirePageSession(w, r, "account:manage")
	if !ok {
		return
	}
	sessions, err := s.auth.ListSessions(r.Context(), session)
	if err != nil {
		s.logger.Warn("session list query failed", "user_id", session.UserID, "error", err)
	}
	s.render(w, "account.html", s.adminData(r, map[string]any{"Title": "Account", "Sessions": sessions}))
}

func (s *Server) handleEmailSettingsPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin/settings/email" {
		http.NotFound(w, r)
		return
	}
	if _, ok := s.requirePageSession(w, r, "email-settings:manage"); !ok {
		return
	}
	settings, err := s.email.SafeSettings(r.Context())
	if err != nil {
		s.logger.Warn("email settings page query failed", "error", err)
	}
	s.render(w, "email_settings.html", s.adminData(r, map[string]any{"Title": "Email Settings", "Settings": settings}))
}

func (s *Server) handleAPIClientsPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin/api-clients" {
		http.NotFound(w, r)
		return
	}
	if !s.requirePage(w, r, "api-client:manage") {
		return
	}
	clients, err := s.clients.ListAPIClients(r.Context())
	if err != nil {
		s.logger.Warn("api client list query failed", "error", err)
	}
	s.render(w, "api_clients.html", s.adminData(r, map[string]any{"Title": "API Clients", "Clients": clients}))
}

func (s *Server) handleNewAPIClientPage(w http.ResponseWriter, r *http.Request) {
	if !s.requirePage(w, r, "api-client:manage") {
		return
	}
	s.render(w, "api_client_new.html", s.adminData(r, map[string]any{"Title": "Create API Client", "Scopes": auth.AllowedAPIScopes()}))
}

func (s *Server) handleAPIClientDetailPage(w http.ResponseWriter, r *http.Request) {
	if !s.requirePage(w, r, "api-client:manage") {
		return
	}
	id, err := uuid.Parse(strings.TrimPrefix(r.URL.Path, "/admin/api-clients/"))
	if err != nil {
		s.render(w, "error.html", map[string]any{"Title": "Unavailable", "Message": "API client metadata is unavailable."})
		return
	}
	client, err := s.clients.APIClientByID(r.Context(), id)
	if err != nil {
		s.render(w, "error.html", map[string]any{"Title": "Unavailable", "Message": "API client metadata is unavailable."})
		return
	}
	s.render(w, "api_client_detail.html", s.adminData(r, map[string]any{"Title": "API Client Detail", "Client": client}))
}

func (s *Server) handleRecipientPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	s.render(w, "recipient.html", map[string]any{"Title": "Secure Secret"})
}

func (s *Server) handleErrorPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "error.html", map[string]any{"Title": "Error", "Message": "The requested action could not be completed."})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	ipHash := middleware.IPHash(s.cfg.RequestIPHashPepper, r)
	isJSON := strings.Contains(r.Header.Get("Content-Type"), "application/json")
	login := ""
	password := ""
	if isJSON {
		var body struct {
			Login    string `json:"login"`
			Username string `json:"username"`
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if !s.decodeJSON(w, r, 2048, &body) {
			return
		}
		login = body.Login
		if login == "" {
			login = body.Username
		}
		if login == "" {
			login = body.Email
		}
		password = body.Password
	} else {
		r.Body = http.MaxBytesReader(w, r.Body, 2048)
		if err := r.ParseForm(); err != nil {
			s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
			return
		}
		login = r.Form.Get("login")
		if login == "" {
			login = r.Form.Get("username")
		}
		password = r.Form.Get("password")
	}

	limitKey := ipHash + ":" + auth.NormalizeLogin(login)
	if !s.limits.Login.Allow(limitKey) {
		s.recordRateLimit("login")
		s.recordLoginFailure()
		s.writeError(w, delivery.CodeRateLimited, "Too many attempts. Try again later.", http.StatusTooManyRequests)
		return
	}
	user, ok, err := auth.Authenticate(r.Context(), s.users, login, password)
	if err != nil {
		s.logger.Warn("login dependency failed", "error", err)
		s.writeError(w, delivery.CodeDependencyUnavailable, "Dependency unavailable.", http.StatusServiceUnavailable)
		return
	}
	if !ok {
		s.recordLoginFailure()
		s.delivery.RecordAudit(r.Context(), delivery.AuditEventRecord{
			Type:      "auth.login_failed",
			Result:    "unauthorized",
			IPHash:    ipHash,
			RequestID: middleware.RequestID(r.Context()),
		})
		s.writeError(w, delivery.CodeUnauthorized, "Unauthorized.", http.StatusUnauthorized)
		return
	}
	if _, err := r.Cookie(auth.CookieName); err == nil {
		s.auth.Destroy(w, r)
	}
	session, err := s.auth.CreateForUser(r.Context(), w, user)
	if err != nil {
		s.writeError(w, delivery.CodeInternal, "Internal error.", http.StatusInternalServerError)
		return
	}
	if err := s.users.TouchLastLogin(r.Context(), user.ID); err != nil {
		s.logger.Warn("last login update failed", "user_id", user.ID, "error", err)
	}
	s.delivery.RecordAudit(r.Context(), delivery.AuditEventRecord{
		ActorID:   user.Username,
		Type:      "auth.login_succeeded",
		Result:    "success",
		IPHash:    ipHash,
		RequestID: middleware.RequestID(r.Context()),
	})
	if !isJSON {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "actor_id": user.Username, "role": user.Role, "csrf_token": s.auth.CSRFToken(session)})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	if bearer := bearerToken(r); bearer != "" && s.cfg.LegacyAdminAPIKeyEnabled && s.validAdminKey(bearer) {
		s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	session, ok := s.auth.FromRequest(r)
	if !ok {
		s.writeError(w, delivery.CodeUnauthorized, "Unauthorized.", http.StatusUnauthorized)
		return
	}
	if !s.validCSRF(r, session) {
		s.recordCSRFFailure()
		s.writeError(w, delivery.CodeForbidden, "Forbidden.", http.StatusForbidden)
		return
	}
	s.delivery.RecordAudit(r.Context(), delivery.AuditEventRecord{
		ActorID:   session.Username,
		Type:      "auth.logout",
		Result:    "success",
		IPHash:    middleware.IPHash(s.cfg.RequestIPHashPepper, r),
		RequestID: middleware.RequestID(r.Context()),
	})
	s.auth.Destroy(w, r)
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleBrowserLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	session, ok := s.auth.FromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !s.validCSRF(r, session) {
		s.recordCSRFFailure()
		s.writeError(w, delivery.CodeForbidden, "Forbidden.", http.StatusForbidden)
		return
	}
	s.delivery.RecordAudit(r.Context(), delivery.AuditEventRecord{
		ActorID:   session.Username,
		Type:      "auth.logout",
		Result:    "success",
		IPHash:    middleware.IPHash(s.cfg.RequestIPHashPepper, r),
		RequestID: middleware.RequestID(r.Context()),
	})
	s.auth.Destroy(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	session, ok := s.auth.FromRequest(r)
	if !ok {
		s.writeError(w, delivery.CodeUnauthorized, "Unauthorized.", http.StatusUnauthorized)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"id":       session.UserID,
		"username": session.Username,
		"email":    session.Email,
		"role":     session.Role,
	})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	session, ok := s.requireAPI(w, r, "account:manage")
	if !ok {
		return
	}
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !s.decodeJSON(w, r, 4096, &body) {
		return
	}
	user, valid, err := auth.Authenticate(r.Context(), s.users, session.Username, body.CurrentPassword)
	if err != nil {
		s.writeError(w, delivery.CodeDependencyUnavailable, "Dependency unavailable.", http.StatusServiceUnavailable)
		return
	}
	if !valid || user.ID != session.UserID {
		s.writeError(w, delivery.CodeUnauthorized, "Unauthorized.", http.StatusUnauthorized)
		return
	}
	if err := auth.ValidateUserPassword(body.NewPassword, s.cfg.AppEnv != "development"); err != nil {
		s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
		return
	}
	if err := s.users.SetPassword(r.Context(), session.UserID, body.NewPassword, false); err != nil {
		s.writeError(w, delivery.CodeInternal, "Internal error.", http.StatusInternalServerError)
		return
	}
	if err := s.auth.RevokeOtherSessions(r.Context(), auth.Session{ID: session.Token, UserID: session.UserID}); err != nil {
		s.logger.Warn("other session revocation failed", "user_id", session.UserID, "error", err)
	}
	s.auth.Destroy(w, r)
	newSession, err := s.auth.CreateForUser(r.Context(), w, user)
	if err != nil {
		s.writeError(w, delivery.CodeInternal, "Internal error.", http.StatusInternalServerError)
		return
	}
	s.delivery.RecordAudit(r.Context(), delivery.AuditEventRecord{
		ActorID:   session.Username,
		Type:      "auth.password_changed",
		Result:    "success",
		IPHash:    middleware.IPHash(s.cfg.RequestIPHashPepper, r),
		RequestID: middleware.RequestID(r.Context()),
	})
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "csrf_token": s.auth.CSRFToken(newSession)})
}

func (s *Server) handleMySessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	session, ok := s.auth.FromRequest(r)
	if !ok {
		s.writeError(w, delivery.CodeUnauthorized, "Unauthorized.", http.StatusUnauthorized)
		return
	}
	sessions, err := s.auth.ListSessions(r.Context(), session)
	if err != nil {
		s.writeError(w, delivery.CodeInternal, "Internal error.", http.StatusInternalServerError)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"items": sessions})
}

func (s *Server) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	session, ok := s.requireAPI(w, r, "account:manage")
	if !ok {
		return
	}
	if err := s.auth.RevokeOtherSessions(r.Context(), auth.Session{ID: session.Token, UserID: session.UserID}); err != nil {
		s.writeError(w, delivery.CodeInternal, "Internal error.", http.StatusInternalServerError)
		return
	}
	s.delivery.RecordAudit(r.Context(), delivery.AuditEventRecord{
		ActorID:   session.Username,
		Type:      "session.revoked",
		Result:    "other_sessions",
		IPHash:    middleware.IPHash(s.cfg.RequestIPHashPepper, r),
		RequestID: middleware.RequestID(r.Context()),
	})
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleUsersAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/users" {
		http.NotFound(w, r)
		return
	}
	actor, ok := s.requireAPI(w, r, "user:manage")
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		users, err := s.users.ListUsers(r.Context())
		if err != nil {
			s.writeError(w, delivery.CodeInternal, "Internal error.", http.StatusInternalServerError)
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"items": users})
	case http.MethodPost:
		var req struct {
			Username            string `json:"username"`
			Email               string `json:"email"`
			Password            string `json:"password"`
			Role                string `json:"role"`
			Status              string `json:"status"`
			ForcePasswordChange bool   `json:"force_password_change"`
		}
		if !s.decodeJSON(w, r, 8192, &req) {
			return
		}
		if err := auth.ValidateUserPassword(req.Password, s.cfg.AppEnv != "development"); err != nil {
			s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
			return
		}
		user, err := s.users.CreateUser(r.Context(), auth.UserCreate{
			Username:            req.Username,
			Email:               req.Email,
			Password:            req.Password,
			Role:                req.Role,
			Status:              req.Status,
			ForcePasswordChange: req.ForcePasswordChange,
		})
		if err != nil {
			s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
			return
		}
		s.delivery.RecordAudit(r.Context(), delivery.AuditEventRecord{
			ActorID:   actor.ActorID,
			Type:      "user.created",
			Result:    "success",
			IPHash:    middleware.IPHash(s.cfg.RequestIPHashPepper, r),
			RequestID: middleware.RequestID(r.Context()),
		})
		s.writeJSON(w, http.StatusCreated, user)
	default:
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUserAPI(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireAPI(w, r, "user:manage")
	if !ok {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	idPart := path
	action := ""
	if before, after, ok := strings.Cut(path, "/"); ok {
		idPart = before
		action = after
	}
	id, err := uuid.Parse(idPart)
	if err != nil {
		s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
		return
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		user, err := s.users.UserByID(r.Context(), id)
		if err != nil {
			s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
			return
		}
		s.writeJSON(w, http.StatusOK, user)
	case action == "" && r.Method == http.MethodPatch:
		var req struct {
			Username            *string `json:"username"`
			Email               *string `json:"email"`
			Role                *string `json:"role"`
			Status              *string `json:"status"`
			ForcePasswordChange *bool   `json:"force_password_change"`
		}
		if !s.decodeJSON(w, r, 8192, &req) {
			return
		}
		user, err := s.users.UpdateUser(r.Context(), id, auth.UserPatch{
			Username:            req.Username,
			Email:               req.Email,
			Role:                req.Role,
			Status:              req.Status,
			ForcePasswordChange: req.ForcePasswordChange,
		})
		if err != nil {
			s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
			return
		}
		s.delivery.RecordAudit(r.Context(), delivery.AuditEventRecord{
			ActorID:   actor.ActorID,
			Type:      "user.updated",
			Result:    "success",
			IPHash:    middleware.IPHash(s.cfg.RequestIPHashPepper, r),
			RequestID: middleware.RequestID(r.Context()),
		})
		s.writeJSON(w, http.StatusOK, user)
	case action == "reset-password" && r.Method == http.MethodPost:
		var req struct {
			Password            string `json:"password"`
			ForcePasswordChange bool   `json:"force_password_change"`
		}
		if !s.decodeJSON(w, r, 8192, &req) {
			return
		}
		if err := auth.ValidateUserPassword(req.Password, s.cfg.AppEnv != "development"); err != nil {
			s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
			return
		}
		if err := s.users.SetPassword(r.Context(), id, req.Password, req.ForcePasswordChange); err != nil {
			s.writeError(w, delivery.CodeInternal, "Internal error.", http.StatusInternalServerError)
			return
		}
		s.delivery.RecordAudit(r.Context(), delivery.AuditEventRecord{
			ActorID:   actor.ActorID,
			Type:      "user.password_reset",
			Result:    "success",
			IPHash:    middleware.IPHash(s.cfg.RequestIPHashPepper, r),
			RequestID: middleware.RequestID(r.Context()),
		})
		s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case action == "disable" && r.Method == http.MethodPost:
		user, err := s.users.SetUserStatus(r.Context(), id, auth.StatusDisabled)
		if err != nil {
			s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
			return
		}
		s.delivery.RecordAudit(r.Context(), delivery.AuditEventRecord{ActorID: actor.ActorID, Type: "user.disabled", Result: "success", IPHash: middleware.IPHash(s.cfg.RequestIPHashPepper, r), RequestID: middleware.RequestID(r.Context())})
		s.writeJSON(w, http.StatusOK, user)
	case action == "enable" && r.Method == http.MethodPost:
		user, err := s.users.SetUserStatus(r.Context(), id, auth.StatusActive)
		if err != nil {
			s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
			return
		}
		s.delivery.RecordAudit(r.Context(), delivery.AuditEventRecord{ActorID: actor.ActorID, Type: "user.enabled", Result: "success", IPHash: middleware.IPHash(s.cfg.RequestIPHashPepper, r), RequestID: middleware.RequestID(r.Context())})
		s.writeJSON(w, http.StatusOK, user)
	default:
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAPIClientsAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/api-clients" {
		http.NotFound(w, r)
		return
	}
	actor, ok := s.requireAPI(w, r, "api-client:manage")
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		clients, err := s.clients.ListAPIClients(r.Context())
		if err != nil {
			s.writeError(w, delivery.CodeInternal, "Internal error.", http.StatusInternalServerError)
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"items": clients})
	case http.MethodPost:
		var req struct {
			Name      string   `json:"name"`
			Scopes    []string `json:"scopes"`
			ExpiresAt string   `json:"expires_at"`
		}
		if !s.decodeJSON(w, r, 8192, &req) {
			return
		}
		expiresAt, err := parseOptionalRFC3339(req.ExpiresAt)
		if err != nil {
			s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
			return
		}
		var owner *uuid.UUID
		if actor.UserID != uuid.Nil {
			ownerID := actor.UserID
			owner = &ownerID
		}
		result, err := auth.CreateAPIClient(r.Context(), s.clients, s.cfg.TokenHMACPepper, auth.APIClientCreate{
			Name:        req.Name,
			OwnerUserID: owner,
			Scopes:      req.Scopes,
			ExpiresAt:   expiresAt,
		})
		if err != nil {
			s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
			return
		}
		s.delivery.RecordAudit(r.Context(), delivery.AuditEventRecord{
			ActorID:   actor.ActorID,
			Type:      "api_client.created",
			Result:    "success",
			IPHash:    middleware.IPHash(s.cfg.RequestIPHashPepper, r),
			RequestID: middleware.RequestID(r.Context()),
		})
		s.writeJSON(w, http.StatusCreated, result)
	default:
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAPIClientAPI(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireAPI(w, r, "api-client:manage")
	if !ok {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/api-clients/")
	idPart := path
	action := ""
	if before, after, ok := strings.Cut(path, "/"); ok {
		idPart = before
		action = after
	}
	id, err := uuid.Parse(idPart)
	if err != nil {
		s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
		return
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		client, err := s.clients.APIClientByID(r.Context(), id)
		if err != nil {
			s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
			return
		}
		s.writeJSON(w, http.StatusOK, client)
	case action == "disable" && r.Method == http.MethodPost:
		client, err := s.clients.SetAPIClientStatus(r.Context(), id, auth.APIClientStatusDisabled)
		if err != nil {
			s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
			return
		}
		s.recordAPIClientAudit(r, actor, "api_client.disabled")
		s.writeJSON(w, http.StatusOK, client)
	case action == "enable" && r.Method == http.MethodPost:
		current, err := s.clients.APIClientByID(r.Context(), id)
		if err != nil || current.Status == auth.APIClientStatusRevoked {
			s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
			return
		}
		client, err := s.clients.SetAPIClientStatus(r.Context(), id, auth.APIClientStatusActive)
		if err != nil {
			s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
			return
		}
		s.recordAPIClientAudit(r, actor, "api_client.enabled")
		s.writeJSON(w, http.StatusOK, client)
	case action == "revoke" && r.Method == http.MethodPost:
		client, err := s.clients.SetAPIClientStatus(r.Context(), id, auth.APIClientStatusRevoked)
		if err != nil {
			s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
			return
		}
		s.recordAPIClientAudit(r, actor, "api_client.revoked")
		s.writeJSON(w, http.StatusOK, client)
	case action == "rotate-secret" && r.Method == http.MethodPost:
		current, err := s.clients.APIClientByID(r.Context(), id)
		if err != nil || current.Status == auth.APIClientStatusRevoked {
			s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
			return
		}
		secret, err := auth.NewAPIClientSecret()
		if err != nil {
			s.writeError(w, delivery.CodeInternal, "Internal error.", http.StatusInternalServerError)
			return
		}
		hash := auth.HashAPIClientSecret(s.cfg.TokenHMACPepper, current.ClientID, secret)
		client, err := s.clients.RotateAPIClientSecret(r.Context(), id, hash)
		if err != nil {
			s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
			return
		}
		s.recordAPIClientAudit(r, actor, "api_client.secret_rotated")
		s.writeJSON(w, http.StatusOK, auth.APIClientCreateResult{APIClient: client, ClientSecret: secret})
	default:
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
	}
}

func (s *Server) recordAPIClientAudit(r *http.Request, actor actor, eventType string) {
	s.delivery.RecordAudit(r.Context(), delivery.AuditEventRecord{
		ActorID:   actor.ActorID,
		Type:      eventType,
		Result:    "success",
		IPHash:    middleware.IPHash(s.cfg.RequestIPHashPepper, r),
		RequestID: middleware.RequestID(r.Context()),
	})
}

func (s *Server) handleSecretLinks(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/secret-links" {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		if _, ok := s.requireAPI(w, r, "secret:read-metadata"); !ok {
			return
		}
		result, err := s.delivery.List(r.Context(), parseListOptions(r))
		if err != nil {
			s.writeDeliveryError(w, err)
			return
		}
		s.writeJSON(w, http.StatusOK, result)
		return
	}
	if r.Method != http.MethodPost {
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	actor, ok := s.requireAPI(w, r, "secret:create")
	if !ok {
		return
	}
	if !s.limits.Create.Allow(actor.ActorID) {
		s.recordRateLimit("create")
		s.writeError(w, delivery.CodeRateLimited, "Rate limit exceeded.", http.StatusTooManyRequests)
		return
	}
	var req delivery.CreateRequest
	if !s.decodeJSON(w, r, s.cfg.MaxSecretBytes+8192, &req) {
		return
	}
	resp, err := s.delivery.Create(r.Context(), actor.ActorID, req)
	if err != nil {
		s.writeDeliveryError(w, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleSecretLinkByID(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/prepare") || strings.HasSuffix(r.URL.Path, "/consume") {
		http.NotFound(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/secret-links/")
	idPart := path
	action := ""
	if before, after, ok := strings.Cut(path, "/"); ok {
		idPart = before
		action = after
	}
	id, err := uuid.Parse(idPart)
	if err != nil {
		s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
		return
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		if _, ok := s.requireAPI(w, r, "secret:read-metadata"); !ok {
			return
		}
		meta, err := s.delivery.Metadata(r.Context(), id)
		if err != nil {
			s.writeDeliveryError(w, err)
			return
		}
		s.writeJSON(w, http.StatusOK, meta)
	case action == "revoke" && r.Method == http.MethodPost:
		actor, ok := s.requireAPI(w, r, "secret:revoke")
		if !ok {
			return
		}
		result, err := s.delivery.Revoke(r.Context(), id, actor.ActorID, middleware.IPHash(s.cfg.RequestIPHashPepper, r), middleware.RequestID(r.Context()))
		if err != nil {
			s.writeDeliveryError(w, err)
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": result.Status, "revoked": result.Revoked})
	default:
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDashboardAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.requireAPI(w, r, "secret:read-metadata"); !ok {
		return
	}
	stats, err := s.delivery.Dashboard(r.Context())
	if err != nil {
		s.writeDeliveryError(w, err)
		return
	}
	stats.Dependencies = s.dependencyState(r.Context())
	s.writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleManualCleanup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	actor, ok := s.requireAPI(w, r, "system:cleanup")
	if !ok {
		return
	}
	result, err := s.delivery.Cleanup(r.Context())
	if err != nil {
		s.writeDeliveryError(w, err)
		return
	}
	s.delivery.RecordAudit(r.Context(), delivery.AuditEventRecord{
		ActorID:   actor.ActorID,
		Type:      "secret.expired",
		Result:    "manual_cleanup",
		IPHash:    middleware.IPHash(s.cfg.RequestIPHashPepper, r),
		RequestID: middleware.RequestID(r.Context()),
	})
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cleanup": result})
}

func (s *Server) handleEmailSettingsAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/settings/email" {
		http.NotFound(w, r)
		return
	}
	actor, ok := s.requireAPI(w, r, "email-settings:manage")
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		settings, err := s.email.SafeSettings(r.Context())
		if err != nil {
			s.writeError(w, delivery.CodeInternal, "Internal error.", http.StatusInternalServerError)
			return
		}
		s.writeJSON(w, http.StatusOK, settings)
	case http.MethodPut:
		var req secureemail.UpdateRequest
		if !s.decodeJSON(w, r, 16*1024, &req) {
			return
		}
		result, err := s.email.Update(r.Context(), actor.UserID, req)
		if err != nil {
			s.writeEmailError(w, err)
			return
		}
		s.recordEmailAudit(r, actor, "email.settings_updated", "success")
		if result.PasswordUpdated {
			s.recordEmailAudit(r, actor, "email.password_updated", "success")
		}
		if result.PasswordCleared {
			s.recordEmailAudit(r, actor, "email.password_cleared", "success")
		}
		s.writeJSON(w, http.StatusOK, result.Settings)
	default:
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleEmailSettingsActionAPI(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireAPI(w, r, "email-settings:manage")
	if !ok {
		return
	}
	action := strings.TrimPrefix(r.URL.Path, "/api/v1/settings/email/")
	switch {
	case action == "test-connection" && r.Method == http.MethodPost:
		result := s.email.TestConnection(r.Context())
		eventType := "email.connection_test_succeeded"
		if !result.OK {
			eventType = "email.connection_test_failed"
		}
		s.recordEmailAudit(r, actor, eventType, result.Result)
		s.writeJSON(w, http.StatusOK, result)
	case action == "send-test" && r.Method == http.MethodPost:
		var req secureemail.SendTestRequest
		if !s.decodeJSON(w, r, 2048, &req) {
			return
		}
		result := s.email.SendTest(r.Context(), req.To)
		eventType := "email.test_delivery_succeeded"
		if !result.OK {
			eventType = "email.test_delivery_failed"
		}
		s.recordEmailAudit(r, actor, eventType, result.Result)
		s.writeJSON(w, http.StatusOK, result)
	case action == "enable" && r.Method == http.MethodPost:
		settings, err := s.email.SetEnabled(r.Context(), actor.UserID, true)
		if err != nil {
			s.writeEmailError(w, err)
			return
		}
		s.recordEmailAudit(r, actor, "email.enabled", "success")
		s.writeJSON(w, http.StatusOK, settings)
	case action == "disable" && r.Method == http.MethodPost:
		settings, err := s.email.SetEnabled(r.Context(), actor.UserID, false)
		if err != nil {
			s.writeEmailError(w, err)
			return
		}
		s.recordEmailAudit(r, actor, "email.disabled", "success")
		s.writeJSON(w, http.StatusOK, settings)
	default:
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
	}
}

func (s *Server) recordEmailAudit(r *http.Request, actor actor, eventType, result string) {
	s.delivery.RecordAudit(r.Context(), delivery.AuditEventRecord{
		ActorID:   actor.ActorID,
		Type:      eventType,
		Result:    result,
		IPHash:    middleware.IPHash(s.cfg.RequestIPHashPepper, r),
		RequestID: middleware.RequestID(r.Context()),
	})
}

func (s *Server) handlePrepare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	ipHash := middleware.IPHash(s.cfg.RequestIPHashPepper, r)
	if !s.limits.Prepare.Allow(ipHash) {
		s.recordRateLimit("prepare")
		s.writeError(w, delivery.CodeRateLimited, "Rate limit exceeded.", http.StatusTooManyRequests)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if !s.decodeJSON(w, r, 4096, &req) {
		return
	}
	resp, err := s.delivery.Prepare(r.Context(), req.Token)
	if err != nil {
		s.writeDeliveryError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleConsume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if !s.decodeJSON(w, r, 4096, &req) {
		return
	}
	consumeKey := middleware.IPHash(s.cfg.RequestIPHashPepper, r) + ":missing"
	if hash, err := securecrypto.TokenHMAC(s.cfg.TokenHMACPepper, req.Token); err == nil {
		consumeKey = middleware.IPHash(s.cfg.RequestIPHashPepper, r) + ":" + base64.RawURLEncoding.EncodeToString(hash[:12])
	}
	if !s.limits.Consume.Allow(consumeKey) {
		s.recordRateLimit("consume")
		s.writeError(w, delivery.CodeRateLimited, "Rate limit exceeded.", http.StatusTooManyRequests)
		return
	}
	resp, err := s.delivery.Consume(r.Context(), req.Token, req.Password)
	if err != nil {
		s.writeDeliveryError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.db.Ping(ctx); err != nil {
		s.writeError(w, delivery.CodeDependencyUnavailable, "Dependency unavailable.", http.StatusServiceUnavailable)
		return
	}
	if err := s.vault.Ready(ctx); err != nil {
		s.writeError(w, delivery.CodeDependencyUnavailable, "Dependency unavailable.", http.StatusServiceUnavailable)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

func (s *Server) requirePage(w http.ResponseWriter, r *http.Request, permission string) bool {
	_, ok := s.requirePageSession(w, r, permission)
	return ok
}

func (s *Server) requirePageSession(w http.ResponseWriter, r *http.Request, permission string) (auth.Session, bool) {
	session, ok := s.auth.FromRequest(r)
	if !ok || !session.Permissions[permission] {
		http.Redirect(w, r, "/login", http.StatusFound)
		return auth.Session{}, false
	}
	return session, true
}

type actor struct {
	ActorID     string
	Permissions map[string]bool
	Bearer      bool
	APIClient   bool
	ClientID    string
	UserID      uuid.UUID
	Username    string
	Email       string
	Role        string
	Token       string
}

func (s *Server) requireAPI(w http.ResponseWriter, r *http.Request, permission string) (actor, bool) {
	if client, ok := s.apiClientActor(r, permission); ok {
		return client, true
	}
	if bearer := bearerToken(r); bearer != "" && s.cfg.LegacyAdminAPIKeyEnabled && s.validAdminKey(bearer) {
		return actor{ActorID: "admin", Permissions: permissionsMap(adminPermissions()), Bearer: true}, true
	}
	if session, ok := s.auth.FromRequest(r); ok && session.Permissions[permission] {
		if isStateChanging(r.Method) && !s.validCSRF(r, session) {
			s.recordCSRFFailure()
			s.writeError(w, delivery.CodeForbidden, "Forbidden.", http.StatusForbidden)
			return actor{}, false
		}
		return actor{
			ActorID:     session.ActorID,
			Permissions: session.Permissions,
			UserID:      session.UserID,
			Username:    session.Username,
			Email:       session.Email,
			Role:        session.Role,
			Token:       session.ID,
		}, true
	}
	s.writeError(w, delivery.CodeUnauthorized, "Unauthorized.", http.StatusUnauthorized)
	return actor{}, false
}

func (s *Server) apiClientActor(r *http.Request, permission string) (actor, bool) {
	clientID, secret, ok := r.BasicAuth()
	if !ok || clientID == "" || secret == "" || s.clients == nil {
		return actor{}, false
	}
	if s.cfg.AppEnv == "production" && !requestHTTPS(r) {
		return actor{}, false
	}
	client, err := s.clients.APIClientByClientID(r.Context(), clientID)
	if err != nil || !auth.IsAPIClientUsable(client.APIClient) || !auth.VerifyAPIClientSecret(s.cfg.TokenHMACPepper, client.ClientID, secret, client.SecretHash) {
		return actor{}, false
	}
	if !auth.ScopeAllowed(client.Scopes, permission) {
		return actor{}, false
	}
	if err := s.clients.TouchAPIClient(r.Context(), client.ID); err != nil {
		s.logger.Warn("api client last used update failed", "client_id", client.ClientID, "error", err)
	}
	return actor{
		ActorID:     "api-client:" + client.ClientID,
		Permissions: scopesMap(client.Scopes),
		APIClient:   true,
		ClientID:    client.ClientID,
	}, true
}

func (s *Server) validAdminKey(value string) bool {
	actual := sha256.Sum256([]byte(value))
	expected := sha256.Sum256([]byte(s.cfg.AdminAPIKey))
	return hmac.Equal(actual[:], expected[:])
}

func (s *Server) recordLoginFailure() {
	if s.metrics != nil {
		s.metrics.LoginFailures.Inc()
	}
}

func (s *Server) recordCSRFFailure() {
	if s.metrics != nil {
		s.metrics.CSRFFailures.Inc()
	}
}

func (s *Server) recordRateLimit(area string) {
	if s.metrics != nil {
		s.metrics.RateLimitEvents.WithLabelValues(area).Inc()
	}
}

func (s *Server) validCSRF(r *http.Request, session auth.Session) bool {
	return s.auth.ValidCSRF(session, csrfTokenFromRequest(r))
}

func csrfTokenFromRequest(r *http.Request) string {
	if token := r.Header.Get("X-CSRF-Token"); token != "" {
		return token
	}
	if strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") ||
		strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
		return r.FormValue("csrf_token")
	}
	return ""
}

func isStateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func bearerToken(r *http.Request) string {
	authz := r.Header.Get("Authorization")
	if authz == "" {
		return ""
	}
	scheme, token, ok := strings.Cut(authz, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

func requestHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func adminPermissions() []string {
	return auth.PermissionsForRole(auth.RoleAdmin)
}

func permissionsMap(values []string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		out[value] = true
	}
	return out
}

func scopesMap(values []string) map[string]bool {
	out := permissionsMap(values)
	if out["secret:list"] {
		out["secret:read-metadata"] = true
	}
	return out
}

func parseOptionalRFC3339(value string) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, err
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, limit int64, dst any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		s.writeError(w, delivery.CodeInvalidRequest, "Content-Type must be application/json.", http.StatusUnsupportedMediaType)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			s.writeError(w, delivery.CodePayloadTooLarge, "Payload too large.", http.StatusRequestEntityTooLarge)
			return false
		}
		s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
		return false
	}
	return true
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		s.logger.Error("template render failed", "template", name, "error", err)
	}
}

func (s *Server) adminData(r *http.Request, values map[string]any) map[string]any {
	values["Env"] = s.cfg.AppEnv
	values["CurrentPath"] = r.URL.Path
	values["ActorID"] = "admin"
	values["Role"] = "admin"
	values["Permissions"] = permissionsMap(adminPermissions())
	if session, ok := s.auth.FromRequest(r); ok {
		values["CSRFToken"] = s.auth.CSRFToken(session)
		values["ActorID"] = session.Username
		values["Role"] = session.Role
		values["Permissions"] = session.Permissions
	}
	return values
}

func (s *Server) dependencyState(ctx context.Context) delivery.DependencyState {
	state := delivery.DependencyState{
		Postgres:        "unavailable",
		Vault:           "unavailable",
		CleanupWorker:   "scheduled",
		CleanupInterval: s.cfg.CleanupInterval.String(),
		LastCleanup:     "not recorded",
		AppVersion:      s.cfg.AppVersion,
	}
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	dbStart := time.Now()
	if s.db != nil && s.db.Ping(pingCtx) == nil {
		state.Postgres = "healthy"
	}
	state.PostgresLatencyMS = time.Since(dbStart).Milliseconds()
	vaultCtx, vaultCancel := context.WithTimeout(ctx, 2*time.Second)
	defer vaultCancel()
	vaultStart := time.Now()
	if s.vault != nil && s.vault.Ready(vaultCtx) == nil {
		state.Vault = "healthy"
	}
	state.VaultLatencyMS = time.Since(vaultStart).Milliseconds()
	return state
}

func parseListOptions(r *http.Request) delivery.ListOptions {
	query := r.URL.Query()
	return delivery.ListOptions{
		Page:        parsePositiveInt(query.Get("page"), 1),
		PageSize:    parsePositiveInt(query.Get("page_size"), 25),
		Status:      query.Get("status"),
		Search:      query.Get("search"),
		CreatedFrom: parseDate(query.Get("created_from")),
		CreatedTo:   parseDate(query.Get("created_to")),
		ExpiresFrom: parseDate(query.Get("expires_from")),
		ExpiresTo:   parseDate(query.Get("expires_to")),
		Sort:        query.Get("sort"),
		Order:       query.Get("order"),
	}
}

func parsePositiveInt(value string, fallback int) int {
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func parseDate(value string) *time.Time {
	if value == "" {
		return nil
	}
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		return nil
	}
	return &parsed
}

func pageURL(r *http.Request, page int) string {
	if page < 1 {
		page = 1
	}
	query := r.URL.Query()
	query.Set("page", strconv.Itoa(page))
	return r.URL.Path + "?" + query.Encode()
}

func statusClass(status string) string {
	switch status {
	case "healthy":
		return "healthy"
	case "unavailable":
		return "unavailable"
	case delivery.StatusActive, delivery.StatusConsuming:
		return "success"
	case delivery.StatusConsumed:
		return "neutral"
	case delivery.StatusExpired:
		return "warning"
	case delivery.StatusRevoked:
		return "danger"
	default:
		return "neutral"
	}
}

func eventLabel(eventType string) string {
	switch eventType {
	case "secret.created":
		return "Secret created"
	case "secret.consumed":
		return "Secret consumed"
	case "secret.revoked":
		return "Secret revoked"
	case "secret.expired":
		return "Secret expired"
	case "secret.password_failed":
		return "Password attempt failed"
	default:
		return eventType
	}
}

func (s *Server) writeDeliveryError(w http.ResponseWriter, err error) {
	status := delivery.ErrorStatus(err)
	code := delivery.ErrorCodeFor(err)
	message := "The request could not be completed."
	if code == delivery.CodeSecretUnavailable {
		message = secretUnavailableMessage()
	}
	if code == delivery.CodePayloadTooLarge {
		message = "Payload too large."
	}
	if code == delivery.CodeInvalidRequest {
		message = "Invalid request."
	}
	if code == delivery.CodeDependencyUnavailable {
		message = "Dependency unavailable."
	}
	s.writeError(w, code, message, status)
}

func (s *Server) writeEmailError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, secureemail.ErrForbidden):
		s.writeError(w, delivery.CodeForbidden, "Forbidden.", http.StatusForbidden)
	case errors.Is(err, secureemail.ErrInvalid):
		s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
	case errors.Is(err, secureemail.ErrNotConfigured):
		s.writeError(w, delivery.CodeInvalidRequest, "Email settings are not configured.", http.StatusUnprocessableEntity)
	case errors.Is(err, secureemail.ErrDependency):
		s.writeError(w, delivery.CodeDependencyUnavailable, "Dependency unavailable.", http.StatusServiceUnavailable)
	default:
		s.writeError(w, delivery.CodeInternal, "Internal error.", http.StatusInternalServerError)
	}
}

func (s *Server) writeError(w http.ResponseWriter, code delivery.ErrorCode, message string, status int) {
	s.writeJSON(w, status, map[string]any{
		"code":    code,
		"message": message,
	})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func secretUnavailableMessage() string {
	return "This secret has expired, was revoked, or has already been viewed."
}
