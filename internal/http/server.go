package server

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"secureshare/internal/auth"
	"secureshare/internal/config"
	securecrypto "secureshare/internal/crypto"
	"secureshare/internal/delivery"
	"secureshare/internal/middleware"
	"secureshare/internal/observability"
	"secureshare/internal/ratelimit"
)

type Dependencies struct {
	Config   config.Config
	Logger   *slog.Logger
	Auth     *auth.SessionManager
	Delivery *delivery.Service
	DB       *pgxpool.Pool
	Vault    delivery.Vault
	Metrics  *observability.Metrics
	Limits   *ratelimit.Registry
}

type Server struct {
	cfg       config.Config
	logger    *slog.Logger
	auth      *auth.SessionManager
	delivery  *delivery.Service
	db        *pgxpool.Pool
	vault     delivery.Vault
	metrics   *observability.Metrics
	limits    *ratelimit.Registry
	templates *template.Template
}

func New(deps Dependencies) *Server {
	funcs := template.FuncMap{
		"formatTime": func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
	}
	templates := template.Must(template.New("").Funcs(funcs).ParseGlob(filepath.Join("web", "templates", "*.html")))
	return &Server{
		cfg:       deps.Config,
		logger:    deps.Logger,
		auth:      deps.Auth,
		delivery:  deps.Delivery,
		db:        deps.DB,
		vault:     deps.Vault,
		metrics:   deps.Metrics,
		limits:    deps.Limits,
		templates: templates,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/login", s.handleLoginPage)
	mux.HandleFunc("/admin", s.handleAdmin)
	mux.HandleFunc("/admin/secrets/new", s.handleNewSecretPage)
	mux.HandleFunc("/admin/secrets/", s.handleSecretPage)
	mux.HandleFunc("/s", s.handleRecipientPage)
	mux.HandleFunc("/error", s.handleErrorPage)
	mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("/api/v1/auth/logout", s.handleLogout)
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
	s.render(w, "login.html", map[string]any{"Title": "Login"})
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if !s.requirePage(w, r, "secret:create") {
		return
	}
	s.render(w, "admin.html", map[string]any{"Title": "SecureShare Admin"})
}

func (s *Server) handleNewSecretPage(w http.ResponseWriter, r *http.Request) {
	if !s.requirePage(w, r, "secret:create") {
		return
	}
	s.render(w, "new_secret.html", map[string]any{"Title": "Create Secret", "MaxTTLHours": int(s.cfg.MaxSecretTTL.Hours())})
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
	s.render(w, "secret_detail.html", map[string]any{"Title": "Secret Metadata", "Secret": meta})
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
	if !s.limits.Login.Allow(ipHash) {
		s.writeError(w, delivery.CodeRateLimited, "Too many attempts. Try again later.", http.StatusTooManyRequests)
		return
	}

	apiKey := ""
	isJSON := strings.Contains(r.Header.Get("Content-Type"), "application/json")
	if isJSON {
		var body struct {
			APIKey string `json:"api_key"`
		}
		if !s.decodeJSON(w, r, 2048, &body) {
			return
		}
		apiKey = body.APIKey
	} else {
		if err := r.ParseForm(); err != nil {
			s.writeError(w, delivery.CodeInvalidRequest, "Invalid request.", http.StatusBadRequest)
			return
		}
		apiKey = r.Form.Get("api_key")
	}

	if !s.validAdminKey(apiKey) {
		s.writeError(w, delivery.CodeUnauthorized, "Unauthorized.", http.StatusUnauthorized)
		return
	}
	if err := s.auth.Create(w, "admin", adminPermissions()); err != nil {
		s.writeError(w, delivery.CodeInternal, "Internal error.", http.StatusInternalServerError)
		return
	}
	if !isJSON {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "actor_id": "admin"})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	s.auth.Destroy(w, r)
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSecretLinks(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/secret-links" {
		http.NotFound(w, r)
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
		if _, ok := s.requireAPI(w, r, "secret:revoke"); !ok {
			return
		}
		ok, err := s.delivery.Revoke(r.Context(), id)
		if err != nil {
			s.writeDeliveryError(w, err)
			return
		}
		if !ok {
			s.writeError(w, delivery.CodeSecretUnavailable, secretUnavailableMessage(), http.StatusGone)
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": delivery.StatusRevoked})
	default:
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePrepare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, delivery.CodeInvalidRequest, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	ipHash := middleware.IPHash(s.cfg.RequestIPHashPepper, r)
	if !s.limits.Prepare.Allow(ipHash) {
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
	session, ok := s.auth.FromRequest(r)
	if !ok || !session.Permissions[permission] {
		http.Redirect(w, r, "/login", http.StatusFound)
		return false
	}
	return true
}

type actor struct {
	ActorID     string
	Permissions map[string]bool
}

func (s *Server) requireAPI(w http.ResponseWriter, r *http.Request, permission string) (actor, bool) {
	if bearer := bearerToken(r); bearer != "" && s.validAdminKey(bearer) {
		return actor{ActorID: "admin", Permissions: permissionsMap(adminPermissions())}, true
	}
	if session, ok := s.auth.FromRequest(r); ok && session.Permissions[permission] {
		return actor{ActorID: session.ActorID, Permissions: session.Permissions}, true
	}
	s.writeError(w, delivery.CodeUnauthorized, "Unauthorized.", http.StatusUnauthorized)
	return actor{}, false
}

func (s *Server) validAdminKey(value string) bool {
	return hmac.Equal([]byte(value), []byte(s.cfg.AdminAPIKey))
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

func adminPermissions() []string {
	return []string{"secret:create", "secret:read-metadata", "secret:revoke"}
}

func permissionsMap(values []string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		out[value] = true
	}
	return out
}

func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, limit int64, dst any) bool {
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
