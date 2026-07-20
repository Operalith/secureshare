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
}

type SessionManager struct {
	secret []byte
	ttl    time.Duration
	secure bool
	mu     sync.RWMutex
	items  map[string]Session
}

func NewSessionManager(secret string, ttl time.Duration, secure bool) *SessionManager {
	return &SessionManager{
		secret: []byte(secret),
		ttl:    ttl,
		secure: secure,
		items:  map[string]Session{},
	}
}

func (m *SessionManager) Create(w http.ResponseWriter, actorID string, permissions []string) error {
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return err
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
	}
	m.mu.Lock()
	m.items[id] = session
	m.mu.Unlock()
	http.SetCookie(w, m.cookie(id, session.ExpiresAt))
	return nil
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
	m.mu.RLock()
	session, ok := m.items[id]
	m.mu.RUnlock()
	if !ok || time.Now().After(session.ExpiresAt) {
		if ok {
			m.mu.Lock()
			delete(m.items, id)
			m.mu.Unlock()
		}
		return Session{}, false
	}
	return session, true
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
