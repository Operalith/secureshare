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
