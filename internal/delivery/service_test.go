package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"secureshare/internal/config"
	"secureshare/internal/observability"
)

func TestValidateCreateRequestEnforcesExpirationAndPayloadLimits(t *testing.T) {
	svc := testService(&fakeStore{}, &fakeVault{})
	valid := CreateRequest{Secret: json.RawMessage(`{"ok":true}`), ExpiresInSeconds: 60, MaxFailedAttempts: 5}
	if err := svc.validateCreate(valid); err != nil {
		t.Fatalf("valid request failed: %v", err)
	}
	tooLong := valid
	tooLong.ExpiresInSeconds = int64((8 * 24 * time.Hour).Seconds())
	if err := svc.validateCreate(tooLong); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected invalid ttl, got %v", err)
	}
	tooLarge := valid
	tooLarge.Secret = json.RawMessage(`"` + strings.Repeat("x", config.DefaultMaxSecretBytes+1) + `"`)
	if err := svc.validateCreate(tooLarge); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected payload too large, got %v", err)
	}
}

func TestSecretUnavailableUsesGenericErrorCode(t *testing.T) {
	if ErrorStatus(ErrSecretUnavailable) != 410 {
		t.Fatal("secret unavailable should map to 410")
	}
	if ErrorCodeFor(ErrSecretUnavailable) != CodeSecretUnavailable {
		t.Fatal("secret unavailable should map to SECRET_UNAVAILABLE")
	}
}

func TestVaultFailureRestoresConsumeLease(t *testing.T) {
	store := &fakeStore{
		candidate: ConsumeCandidate{
			ID:               uuid.New(),
			EncryptedPayload: "vault:v1:bad",
		},
	}
	vault := &fakeVault{decryptErr: errors.New("vault down")}
	svc := testService(store, vault)

	_, err := svc.Consume(context.Background(), "raw-token", "")
	if !errors.Is(err, ErrDependencyUnavailable) {
		t.Fatalf("expected dependency error, got %v", err)
	}
	if !store.restored {
		t.Fatal("expected consume lease to be restored")
	}
	if store.completed {
		t.Fatal("vault failure must not complete consumption")
	}
}

func testService(store Store, vault Vault) *Service {
	cfg := config.Config{
		AppBaseURL:        "http://localhost:8080",
		TokenHMACPepper:   "test-pepper-with-enough-length",
		MaxSecretTTL:      7 * 24 * time.Hour,
		DefaultSecretTTL:  24 * time.Hour,
		ConsumingLeaseTTL: 30 * time.Second,
		MaxSecretBytes:    config.DefaultMaxSecretBytes,
	}
	return NewService(cfg, store, vault, observability.New(), slog.Default())
}

type fakeVault struct {
	decryptErr error
}

func (v *fakeVault) Encrypt(context.Context, []byte) (string, error) {
	return "vault:v1:test", nil
}

func (v *fakeVault) Decrypt(context.Context, string) ([]byte, error) {
	if v.decryptErr != nil {
		return nil, v.decryptErr
	}
	return []byte(`{"ok":true}`), nil
}

func (v *fakeVault) Ready(context.Context) error {
	return nil
}

type fakeStore struct {
	candidate ConsumeCandidate
	restored  bool
	completed bool
}

func (s *fakeStore) Insert(context.Context, InsertParams) error { return nil }
func (s *fakeStore) Metadata(context.Context, uuid.UUID) (Metadata, error) {
	return Metadata{}, nil
}
func (s *fakeStore) List(context.Context, ListOptions) (ListResult, error) {
	return ListResult{}, nil
}
func (s *fakeStore) Dashboard(context.Context) (DashboardStats, error) {
	return DashboardStats{}, nil
}
func (s *fakeStore) RecentActivity(context.Context, int) ([]ActivityEvent, error) {
	return nil, nil
}
func (s *fakeStore) Revoke(context.Context, uuid.UUID) (RevokeResult, error) {
	return RevokeResult{Status: StatusRevoked, Revoked: true, Found: true}, nil
}
func (s *fakeStore) RecordAuditEvent(context.Context, AuditEventRecord) error { return nil }
func (s *fakeStore) Prepare(context.Context, []byte) (PrepareResponse, error) {
	return PrepareResponse{MayAttempt: true}, nil
}
func (s *fakeStore) BeginConsume(context.Context, []byte, uuid.UUID, time.Duration) (ConsumeCandidate, bool, error) {
	if s.candidate.ID == uuid.Nil {
		s.candidate.ID = uuid.New()
	}
	return s.candidate, true, nil
}
func (s *fakeStore) RecordPasswordFailure(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func (s *fakeStore) RestoreConsume(context.Context, uuid.UUID, uuid.UUID) error {
	s.restored = true
	return nil
}
func (s *fakeStore) CompleteConsume(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
	s.completed = true
	return true, nil
}
func (s *fakeStore) Cleanup(context.Context, time.Duration, time.Duration, time.Duration, time.Duration, time.Duration) (CleanupResult, error) {
	return CleanupResult{}, nil
}
func (s *fakeStore) CountActive(context.Context) (float64, error) { return 0, nil }
