package auth

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"secureshare/internal/config"
)

func TestBootstrapAdminCreationIsIdempotent(t *testing.T) {
	store := NewMemoryStore()
	cfg := config.Config{
		AppEnv:                 "development",
		BootstrapAdminUsername: "admin",
		BootstrapAdminEmail:    "admin@example.local",
		BootstrapAdminPassword: "change-me-now",
	}
	if err := BootstrapAdmin(context.Background(), store, cfg); err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}
	if err := BootstrapAdmin(context.Background(), store, cfg); err != nil {
		t.Fatalf("second bootstrap failed: %v", err)
	}
	count, err := store.CountUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("users = %d, want 1", count)
	}
}

func TestAuthenticateByUsernameAndEmail(t *testing.T) {
	store := NewMemoryStore()
	user, err := store.CreateUser(context.Background(), UserCreate{
		Username: "developer1",
		Email:    "developer1@example.local",
		Password: "correct passphrase",
		Role:     RoleDeveloper,
		Status:   StatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, login := range []string{"developer1", "developer1@example.local"} {
		t.Run(login, func(t *testing.T) {
			got, ok, err := Authenticate(context.Background(), store, login, "correct passphrase")
			if err != nil || !ok {
				t.Fatalf("authenticate failed ok=%v err=%v", ok, err)
			}
			if got.ID != user.ID {
				t.Fatalf("authenticated id = %s, want %s", got.ID, user.ID)
			}
		})
	}
}

func TestAuthenticateRejectsInvalidAndDisabledUsers(t *testing.T) {
	store := NewMemoryStore()
	user, err := store.CreateUser(context.Background(), UserCreate{
		Username: "viewer1",
		Email:    "viewer1@example.local",
		Password: "correct passphrase",
		Role:     RoleViewer,
		Status:   StatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := Authenticate(context.Background(), store, "viewer1", "wrong"); err != nil || ok {
		t.Fatalf("invalid password ok=%v err=%v, want false nil", ok, err)
	}
	if _, err := store.SetUserStatus(context.Background(), user.ID, StatusDisabled); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := Authenticate(context.Background(), store, "viewer1", "correct passphrase"); err != nil || ok {
		t.Fatalf("disabled login ok=%v err=%v, want false nil", ok, err)
	}
}

func TestDatabaseBackedSessionExpiryAndIdleTimeout(t *testing.T) {
	store := NewMemoryStore()
	user, err := store.CreateUser(context.Background(), UserCreate{
		Username: "admin",
		Email:    "admin@example.local",
		Password: "correct passphrase",
		Role:     RoleAdmin,
		Status:   StatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	manager := NewSessionManager("test-session-secret-with-enough-length", "test-csrf-secret-with-enough-length", 25*time.Millisecond, 10*time.Millisecond, false).WithStore(store)
	rec := httptest.NewRecorder()
	session, err := manager.CreateForUser(context.Background(), rec, user)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(rec.Result().Cookies()[0])
	if _, ok := manager.FromRequest(req); !ok {
		t.Fatal("fresh session was not accepted")
	}
	time.Sleep(5 * time.Millisecond)
	if _, ok := manager.FromRequest(req); !ok {
		t.Fatal("session should be accepted after last_seen refresh")
	}
	time.Sleep(30 * time.Millisecond)
	if _, ok := manager.FromRequest(req); ok {
		t.Fatal("expired session was accepted")
	}
	if token := manager.CSRFToken(session); token == "" {
		t.Fatal("csrf token was empty")
	}
}
