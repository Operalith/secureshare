package email

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"secureshare/internal/config"
	"secureshare/internal/observability"
)

func TestSettingsUpdateEncryptsRedactsPreservesAndClearsPassword(t *testing.T) {
	store := NewMemoryStore()
	vault := &testVault{}
	service := NewService(testConfig("development"), store, vault, observability.New(), nil)
	req := validUpdateRequest()
	req.SMTPPassword = "smtp-redaction-canary"
	result, err := service.Update(context.Background(), uuidForTest(), req)
	if err != nil {
		t.Fatalf("update settings: %v", err)
	}
	if !result.Settings.PasswordConfigured {
		t.Fatal("safe settings did not report configured password")
	}
	raw, err := json.Marshal(result.Settings)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "smtp-redaction-canary") || strings.Contains(string(raw), "smtp_password") || strings.Contains(string(raw), "ciphertext") {
		t.Fatalf("safe settings leaked password material: %s", raw)
	}
	stored := store.StoredForTest()
	if stored.SMTPPasswordCiphertext == "" || strings.Contains(stored.SMTPPasswordCiphertext, "smtp-redaction-canary") {
		t.Fatalf("SMTP password was not encrypted: %q", stored.SMTPPasswordCiphertext)
	}
	originalCiphertext := stored.SMTPPasswordCiphertext

	req.SMTPPassword = ""
	result, err = service.Update(context.Background(), uuidForTest(), req)
	if err != nil {
		t.Fatalf("preserve password update: %v", err)
	}
	if got := store.StoredForTest().SMTPPasswordCiphertext; got != originalCiphertext {
		t.Fatalf("empty password update changed ciphertext: got %q want %q", got, originalCiphertext)
	}
	if !result.Settings.PasswordConfigured {
		t.Fatal("preserved password was not reported as configured")
	}

	req.ClearSMTPPassword = true
	result, err = service.Update(context.Background(), uuidForTest(), req)
	if err != nil {
		t.Fatalf("clear password update: %v", err)
	}
	if result.Settings.PasswordConfigured {
		t.Fatal("cleared password still reported as configured")
	}
	if got := store.StoredForTest().SMTPPasswordCiphertext; got != "" {
		t.Fatalf("clear password left ciphertext: %q", got)
	}
}

func TestSettingsValidationRejectsInvalidInputs(t *testing.T) {
	service := NewService(testConfig("development"), NewMemoryStore(), &testVault{}, observability.New(), nil)
	for name, mutate := range map[string]func(*UpdateRequest){
		"missing host":  func(req *UpdateRequest) { req.SMTPHost = "" },
		"invalid port":  func(req *UpdateRequest) { req.SMTPPort = 70000 },
		"invalid email": func(req *UpdateRequest) { req.FromEmail = "not-an-email" },
	} {
		t.Run(name, func(t *testing.T) {
			req := validUpdateRequest()
			mutate(&req)
			if _, err := service.Update(context.Background(), uuidForTest(), req); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestProductionRejectsUnencryptedSMTP(t *testing.T) {
	service := NewService(testConfig("production"), NewMemoryStore(), &testVault{}, observability.New(), nil)
	req := validUpdateRequest()
	req.EncryptionMode = EncryptionNone
	if _, err := service.Update(context.Background(), uuidForTest(), req); err == nil {
		t.Fatal("expected production unencrypted SMTP rejection")
	}
}

func validUpdateRequest() UpdateRequest {
	return UpdateRequest{
		Enabled:                  true,
		SMTPHost:                 "smtp.example.local",
		SMTPPort:                 587,
		EncryptionMode:           EncryptionStartTLS,
		SMTPUsername:             "smtp-user",
		FromName:                 "SecureShare",
		FromEmail:                "secureshare@example.local",
		ConnectionTimeoutSeconds: 5,
		SendTimeoutSeconds:       10,
		DefaultSubject:           DefaultSubject,
		DefaultMessage:           DefaultMessage,
	}
}

func testConfig(env string) config.Config {
	return config.Config{
		AppEnv:              env,
		AppBaseURL:          "http://localhost:8080",
		TokenHMACPepper:     "test-pepper-with-enough-length",
		SessionSecret:       "test-session-secret-with-enough-length",
		CSRFSecret:          "test-csrf-secret-with-enough-length",
		RequestIPHashPepper: "ip-pepper-with-enough-length",
	}
}

func uuidForTest() uuid.UUID {
	return uuid.MustParse("22222222-2222-4222-8222-222222222222")
}

type testVault struct{}

func (v *testVault) Encrypt(_ context.Context, value []byte) (string, error) {
	return "vault:v1:" + base64.RawURLEncoding.EncodeToString(value), nil
}

func (v *testVault) Decrypt(_ context.Context, ciphertext string) ([]byte, error) {
	raw := strings.TrimPrefix(ciphertext, "vault:v1:")
	return base64.RawURLEncoding.DecodeString(raw)
}

func (v *testVault) Ready(context.Context) error { return nil }
