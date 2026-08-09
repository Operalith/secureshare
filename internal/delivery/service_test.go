package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"secureshare/internal/auth"
	"secureshare/internal/config"
	"secureshare/internal/observability"
)

func TestValidateCreateRequestEnforcesExpirationAndPayloadLimits(t *testing.T) {
	svc := testService(&fakeStore{}, &fakeVault{})
	valid := CreateRequest{Secret: json.RawMessage(`{"ok":true}`), ExpiresInSeconds: 60, MaxFailedAttempts: 5}
	payload, _, err := svc.canonicalPayload(valid)
	if err != nil {
		t.Fatalf("canonical payload failed: %v", err)
	}
	if err := svc.validateCreate(valid, payload); err != nil {
		t.Fatalf("valid request failed: %v", err)
	}
	tooLong := valid
	tooLong.ExpiresInSeconds = int64((8 * 24 * time.Hour).Seconds())
	if err := svc.validateCreate(tooLong, payload); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected invalid ttl, got %v", err)
	}
	tooLarge := valid
	tooLarge.Secret = json.RawMessage(`"` + strings.Repeat("x", config.DefaultMaxSecretBytes+1) + `"`)
	largePayload, _, err := svc.canonicalPayload(tooLarge)
	if err != nil {
		t.Fatalf("large canonical payload failed: %v", err)
	}
	if err := svc.validateCreate(tooLarge, largePayload); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected payload too large, got %v", err)
	}
}

func TestCanonicalPayloadSupportsMixedCredentialShapes(t *testing.T) {
	svc := testService(&fakeStore{}, &fakeVault{})
	cases := map[string]CreateRequest{
		"username password": {
			Payload: &SecretPayload{Type: "structured", Fields: []StructuredSecretField{
				{Name: "username", Label: "Username", Value: "merchant-1001"},
				{Name: "password", Label: "Password", Value: "temporary-password", Sensitive: true},
			}},
		},
		"api key only": {
			Payload: &SecretPayload{Type: "structured", Fields: []StructuredSecretField{
				{Name: "api_key", Label: "API Key", Value: "example-api-key", Sensitive: true},
			}},
		},
		"combined": {
			Payload: &SecretPayload{Type: "structured", Fields: []StructuredSecretField{
				{Name: "username", Label: "Username", Value: "merchant-1001"},
				{Name: "password", Label: "Password", Value: "temporary-password", Sensitive: true},
				{Name: "api_key", Label: "API Key", Value: "example-api-key", Sensitive: true},
			}},
		},
		"client credentials": {
			Payload: &SecretPayload{Type: "structured", Fields: []StructuredSecretField{
				{Name: "client_id", Label: "Client ID", Value: "client-123"},
				{Name: "client_secret", Label: "Client Secret", Value: "client-secret", Sensitive: true},
			}},
		},
		"text": {Payload: &SecretPayload{Type: "text", Text: "line one\nline two"}},
		"json": {Payload: &SecretPayload{Type: "json", Value: json.RawMessage(`{"username":"merchant-1001","password":"temporary-password"}`)}},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			raw, summary, err := svc.canonicalPayload(req)
			if err != nil {
				t.Fatalf("canonical payload failed: %v", err)
			}
			if !json.Valid(raw) {
				t.Fatal("canonical payload was not JSON")
			}
			if req.Payload.Type == "structured" && summary.FieldCount != len(req.Payload.Fields) {
				t.Fatalf("field count = %d, want %d", summary.FieldCount, len(req.Payload.Fields))
			}
		})
	}
}

func TestCanonicalPayloadRejectsInvalidStructuredFields(t *testing.T) {
	svc := testService(&fakeStore{}, &fakeVault{})
	for _, req := range []CreateRequest{
		{Payload: &SecretPayload{Type: "structured"}},
		{Payload: &SecretPayload{Type: "structured", Fields: []StructuredSecretField{{Name: "bad name", Label: "Bad", Value: "x"}}}},
		{Payload: &SecretPayload{Type: "structured", Fields: []StructuredSecretField{{Name: "duplicate", Value: "1"}, {Name: "DUPLICATE", Value: "2"}}}},
		{Payload: &SecretPayload{Type: "structured", Fields: tooManyFields()}},
	} {
		if _, _, err := svc.canonicalPayload(req); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("expected invalid request, got %v", err)
		}
	}
}

func TestLegacySecretRequestsRemainCompatible(t *testing.T) {
	svc := testService(&fakeStore{}, &fakeVault{})
	raw, summary, err := svc.canonicalPayload(CreateRequest{Secret: json.RawMessage(`{"value":"legacy"}`)})
	if err != nil {
		t.Fatalf("legacy canonical payload failed: %v", err)
	}
	if summary.Type != "json" {
		t.Fatalf("legacy payload type = %q, want json", summary.Type)
	}
	canonical, legacy, err := normalizeConsumedPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(canonical), `"type":"json"`) {
		t.Fatalf("canonical payload did not contain json type: %s", canonical)
	}
	if string(legacy) != `{"value":"legacy"}` {
		t.Fatalf("legacy projection = %s", legacy)
	}
}

func tooManyFields() []StructuredSecretField {
	fields := make([]StructuredSecretField, 51)
	for i := range fields {
		fields[i] = StructuredSecretField{Name: "field" + strconv.Itoa(i), Value: "x"}
	}
	return fields
}

func TestSecretUnavailableUsesGenericErrorCode(t *testing.T) {
	if ErrorStatus(ErrSecretUnavailable) != 410 {
		t.Fatal("secret unavailable should map to 410")
	}
	if ErrorCodeFor(ErrSecretUnavailable) != CodeSecretUnavailable {
		t.Fatal("secret unavailable should map to SECRET_UNAVAILABLE")
	}
}

func TestLinkPasswordInvalidUsesDedicatedUnauthorizedError(t *testing.T) {
	if ErrorStatus(ErrLinkPasswordInvalid) != 401 {
		t.Fatal("invalid link password should map to 401")
	}
	if ErrorCodeFor(ErrLinkPasswordInvalid) != CodeLinkPasswordInvalid {
		t.Fatal("invalid link password should map to LINK_PASSWORD_INVALID")
	}
}

func TestWrongPasswordDoesNotAcquireLeaseAndAllowsRetry(t *testing.T) {
	hash, err := auth.HashPassword("correct-password")
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{candidate: ConsumeCandidate{ID: uuid.New(), EncryptedPayload: "vault:v1:test", PasswordHash: &hash}}
	svc := testService(store, &fakeVault{})

	if _, err := svc.Consume(context.Background(), "raw-token", "wrong-password"); !errors.Is(err, ErrLinkPasswordInvalid) {
		t.Fatalf("wrong password error = %v, want LINK_PASSWORD_INVALID", err)
	}
	if store.beginCalls != 0 {
		t.Fatalf("wrong password acquired %d consume leases, want 0", store.beginCalls)
	}
	if store.passwordFailures != 1 {
		t.Fatalf("password failures = %d, want 1", store.passwordFailures)
	}

	if _, err := svc.Consume(context.Background(), "raw-token", "correct-password"); err != nil {
		t.Fatalf("correct retry failed: %v", err)
	}
	if store.beginCalls != 1 || !store.completed {
		t.Fatal("correct retry did not complete exactly one consume lease")
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

func TestPasswordProtectionManagementHashesResetsAndAudits(t *testing.T) {
	id := uuid.New()
	store := &fakeStore{
		protectionResult: ProtectionUpdateResult{ID: id, Updated: true},
	}
	svc := testService(store, &fakeVault{})

	result, err := svc.SetPasswordProtection(context.Background(), id, "new-link-password", "developer:alice", "ip-hash", "request-id")
	if err != nil {
		t.Fatalf("set password protection failed: %v", err)
	}
	if !result.Updated || store.updatedPasswordHash == nil {
		t.Fatal("set password protection did not persist a password hash")
	}
	if *store.updatedPasswordHash == "new-link-password" || !auth.VerifyPassword("new-link-password", *store.updatedPasswordHash) {
		t.Fatal("set password protection did not use a verifiable Argon2id hash")
	}
	if got := store.auditEvents[len(store.auditEvents)-1]; got.Type != "secret.password_set" || got.ActorID != "developer:alice" {
		t.Fatalf("set audit event = %#v", got)
	}

	store.protectionResult.WasProtected = true
	if _, err := svc.SetPasswordProtection(context.Background(), id, "replacement-password", "admin", "ip-hash", "request-id-2"); err != nil {
		t.Fatalf("replace password protection failed: %v", err)
	}
	if got := store.auditEvents[len(store.auditEvents)-1]; got.Type != "secret.password_replaced" {
		t.Fatalf("replace audit event = %#v", got)
	}

	if _, err := svc.RemovePasswordProtection(context.Background(), id, "admin", "ip-hash", "request-id-3"); err != nil {
		t.Fatalf("remove password protection failed: %v", err)
	}
	if store.updatedPasswordHash != nil {
		t.Fatal("remove password protection did not clear the password hash")
	}
	if got := store.auditEvents[len(store.auditEvents)-1]; got.Type != "secret.password_removed" {
		t.Fatalf("remove audit event = %#v", got)
	}
}

func TestPasswordProtectionManagementRejectsInvalidOrUnavailableLinks(t *testing.T) {
	store := &fakeStore{}
	svc := testService(store, &fakeVault{})
	if _, err := svc.SetPasswordProtection(context.Background(), uuid.New(), " ", "admin", "", ""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty password error = %v, want invalid request", err)
	}
	if store.protectionUpdates != 0 {
		t.Fatal("invalid password reached persistence")
	}
	if _, err := svc.SetPasswordProtection(context.Background(), uuid.New(), "new-password", "admin", "", ""); !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("inactive link error = %v, want unavailable", err)
	}
	if _, err := svc.RemovePasswordProtection(context.Background(), uuid.New(), "admin", "", ""); !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("inactive link removal error = %v, want unavailable", err)
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
	candidate           ConsumeCandidate
	restored            bool
	completed           bool
	beginCalls          int
	passwordFailures    int
	protectionResult    ProtectionUpdateResult
	protectionUpdates   int
	updatedPasswordHash *string
	auditEvents         []AuditEventRecord
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
func (s *fakeStore) RecordAuditEvent(_ context.Context, event AuditEventRecord) error {
	s.auditEvents = append(s.auditEvents, event)
	return nil
}
func (s *fakeStore) Prepare(context.Context, []byte) (PrepareResponse, error) {
	return PrepareResponse{MayAttempt: true}, nil
}
func (s *fakeStore) FindConsumeCandidate(context.Context, []byte, time.Duration) (ConsumeCandidate, bool, error) {
	if s.candidate.ID == uuid.Nil {
		s.candidate.ID = uuid.New()
	}
	return s.candidate, true, nil
}
func (s *fakeStore) BeginConsume(context.Context, []byte, *string, uuid.UUID, time.Duration) (ConsumeCandidate, bool, error) {
	s.beginCalls++
	if s.candidate.ID == uuid.Nil {
		s.candidate.ID = uuid.New()
	}
	return s.candidate, true, nil
}
func (s *fakeStore) RecordPasswordFailure(context.Context, []byte, string, time.Duration) (PasswordFailureResult, error) {
	s.passwordFailures++
	return PasswordFailureResult{ID: s.candidate.ID, Updated: true}, nil
}
func (s *fakeStore) UpdatePasswordProtection(_ context.Context, _ uuid.UUID, passwordHash *string) (ProtectionUpdateResult, error) {
	s.protectionUpdates++
	s.updatedPasswordHash = passwordHash
	return s.protectionResult, nil
}
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
