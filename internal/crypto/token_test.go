package crypto

import (
	"encoding/base64"
	"testing"
)

func TestGenerateTokenHas256BitsAndIsURLSafe(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token was not raw URL-safe base64: %v", err)
	}
	if len(raw) != TokenBytes {
		t.Fatalf("token raw length = %d, want %d", len(raw), TokenBytes)
	}
}

func TestTokenHMACDeterministicAndPeppered(t *testing.T) {
	hash1, err := TokenHMAC("pepper-one", "token")
	if err != nil {
		t.Fatal(err)
	}
	hash2, err := TokenHMAC("pepper-one", "token")
	if err != nil {
		t.Fatal(err)
	}
	hash3, err := TokenHMAC("pepper-two", "token")
	if err != nil {
		t.Fatal(err)
	}
	if !ConstantTimeEqual(hash1, hash2) {
		t.Fatal("same pepper and token produced different hashes")
	}
	if ConstantTimeEqual(hash1, hash3) {
		t.Fatal("different pepper produced the same hash")
	}
	if len(hash1) != 32 {
		t.Fatalf("hash length = %d, want 32", len(hash1))
	}
}
