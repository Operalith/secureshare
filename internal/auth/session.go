package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"
)

const CookieName = "ss_session"

type Session struct {
	ID          string
	ActorID     string
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

func (m *SessionManager) Destroy(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(CookieName); err == nil {
		if id, ok := m.unsign(cookie.Value); ok {
			m.mu.Lock()
			delete(m.items, id)
			m.mu.Unlock()
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
