package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const CookieName = "ss_session"

type Session struct {
	ID          string
	SessionID   uuid.UUID
	UserID      uuid.UUID
	ActorID     string
	Username    string
	Email       string
	Role        string
	Permissions map[string]bool
	ExpiresAt   time.Time
	LastSeenAt  time.Time
}

type SessionManager struct {
	secret      []byte
	csrfSecret  []byte
	ttl         time.Duration
	idleTimeout time.Duration
	secure      bool
	store       UserStore
	mu          sync.RWMutex
	items       map[string]Session
}

func NewSessionManager(secret, csrfSecret string, ttl, idleTimeout time.Duration, secure bool) *SessionManager {
	return &SessionManager{
		secret:      []byte(secret),
		csrfSecret:  []byte(csrfSecret),
		ttl:         ttl,
		idleTimeout: idleTimeout,
		secure:      secure,
		items:       map[string]Session{},
	}
}

func (m *SessionManager) WithStore(store UserStore) *SessionManager {
	m.store = store
	return m
}

func (m *SessionManager) Create(w http.ResponseWriter, actorID string, permissions []string) (Session, error) {
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return Session{}, err
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)
	perms := map[string]bool{}
	for _, permission := range permissions {
		perms[permission] = true
	}
	session := Session{
		ID:          id,
		ActorID:     actorID,
		Permissions: perms,
		ExpiresAt:   time.Now().Add(m.ttl),
		LastSeenAt:  time.Now(),
	}
	m.mu.Lock()
	m.items[id] = session
	m.mu.Unlock()
	http.SetCookie(w, m.cookie(id, session.ExpiresAt))
	return session, nil
}

func (m *SessionManager) CreateForUser(ctx context.Context, w http.ResponseWriter, user User) (Session, error) {
	if m.store == nil {
		return m.Create(w, user.Username, PermissionsForRole(user.Role))
	}
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return Session{}, err
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)
	now := time.Now().UTC()
	expiresAt := now.Add(m.ttl)
	sessionID, err := m.store.CreateSession(ctx, user.ID, m.tokenHash(id), expiresAt, now)
	if err != nil {
		return Session{}, err
	}
	session := Session{
		ID:          id,
		SessionID:   sessionID,
		UserID:      user.ID,
		ActorID:     user.Username,
		Username:    user.Username,
		Email:       user.Email,
		Role:        user.Role,
		Permissions: permissionsMap(PermissionsForRole(user.Role)),
		ExpiresAt:   expiresAt,
		LastSeenAt:  now,
	}
	http.SetCookie(w, m.cookie(id, session.ExpiresAt))
	return session, nil
}

func (m *SessionManager) Destroy(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(CookieName); err == nil {
		if id, ok := m.unsign(cookie.Value); ok {
			if m.store != nil {
				_ = m.store.RevokeSession(r.Context(), m.tokenHash(id))
			} else {
				m.mu.Lock()
				delete(m.items, id)
				m.mu.Unlock()
			}
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   m.secure,
	})
}

func (m *SessionManager) FromRequest(r *http.Request) (Session, bool) {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return Session{}, false
	}
	id, ok := m.unsign(cookie.Value)
	if !ok {
		return Session{}, false
	}
	now := time.Now()
	if m.store != nil {
		user, sessionID, expiresAt, lastSeenAt, err := m.store.SessionByHash(r.Context(), m.tokenHash(id), now.UTC(), m.idleTimeout)
		if err != nil {
			return Session{}, false
		}
		return Session{
			ID:          id,
			SessionID:   sessionID,
			UserID:      user.ID,
			ActorID:     user.Username,
			Username:    user.Username,
			Email:       user.Email,
			Role:        user.Role,
			Permissions: permissionsMap(PermissionsForRole(user.Role)),
			ExpiresAt:   expiresAt,
			LastSeenAt:  lastSeenAt,
		}, true
	}
	m.mu.RLock()
	session, ok := m.items[id]
	m.mu.RUnlock()
	if !ok || now.After(session.ExpiresAt) || (m.idleTimeout > 0 && now.Sub(session.LastSeenAt) > m.idleTimeout) {
		if ok {
			m.mu.Lock()
			delete(m.items, id)
			m.mu.Unlock()
		}
		return Session{}, false
	}
	session.LastSeenAt = now
	m.mu.Lock()
	m.items[id] = session
	m.mu.Unlock()
	return session, true
}

func (m *SessionManager) RevokeOtherSessions(ctx context.Context, session Session) error {
	if m.store == nil {
		return nil
	}
	return m.store.RevokeOtherSessions(ctx, session.UserID, m.tokenHash(session.ID))
}

func (m *SessionManager) ListSessions(ctx context.Context, session Session) ([]SessionInfo, error) {
	if m.store == nil {
		return nil, nil
	}
	return m.store.ListSessions(ctx, session.UserID, m.tokenHash(session.ID))
}

func (m *SessionManager) CSRFToken(session Session) string {
	mac := hmac.New(sha256.New, m.csrfSecret)
	_, _ = mac.Write([]byte(session.ID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (m *SessionManager) ValidCSRF(session Session, token string) bool {
	if token == "" {
		return false
	}
	expected := m.CSRFToken(session)
	return hmac.Equal([]byte(token), []byte(expected))
}

func (m *SessionManager) TokenHashForRequest(r *http.Request) ([]byte, bool) {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return nil, false
	}
	id, ok := m.unsign(cookie.Value)
	if !ok {
		return nil, false
	}
	return m.tokenHash(id), true
}

func (m *SessionManager) cookie(id string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    m.sign(id),
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   m.secure,
	}
}

func (m *SessionManager) sign(id string) string {
	mac := hmac.New(sha256.New, m.secret)
	_, _ = mac.Write([]byte(id))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return id + "." + sig
}

func (m *SessionManager) unsign(value string) (string, bool) {
	id, sig, ok := strings.Cut(value, ".")
	if !ok || id == "" || sig == "" {
		return "", false
	}
	expected := m.sign(id)
	return id, hmac.Equal([]byte(value), []byte(expected))
}

func (m *SessionManager) tokenHash(id string) []byte {
	mac := hmac.New(sha256.New, m.secret)
	_, _ = mac.Write([]byte("session-token:"))
	_, _ = mac.Write([]byte(id))
	return mac.Sum(nil)
}

func permissionsMap(values []string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		out[value] = true
	}
	return out
}
