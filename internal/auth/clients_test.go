package auth

import (
	"context"
	"testing"
	"time"
)

func TestAPIClientSecretHashAndScopes(t *testing.T) {
	pepper := "api-client-test-pepper-with-enough-length"
	clientID := "ssc_testclient"
	secret := "sscs_testsecret"
	hash := HashAPIClientSecret(pepper, clientID, secret)
	if hash == "" || hash == secret {
		t.Fatal("client secret hash was empty or equal to the plaintext secret")
	}
	if !VerifyAPIClientSecret(pepper, clientID, secret, hash) {
		t.Fatal("valid client secret did not verify")
	}
	if VerifyAPIClientSecret(pepper, clientID, "wrong", hash) {
		t.Fatal("invalid client secret verified")
	}

	scopes, err := NormalizeScopes([]string{" secret:create ", "secret:create", "secret:list"})
	if err != nil {
		t.Fatalf("normalize scopes failed: %v", err)
	}
	if len(scopes) != 2 || scopes[0] != "secret:create" || scopes[1] != "secret:list" {
		t.Fatalf("unexpected normalized scopes: %#v", scopes)
	}
	if _, err := NormalizeScopes([]string{"user:manage"}); err == nil {
		t.Fatal("invalid scope was accepted")
	}
	if !ScopeAllowed([]string{"secret:list"}, "secret:read-metadata") {
		t.Fatal("secret:list should allow metadata reads")
	}
}

func TestMemoryAPIClientRotationRevocationAndExpiration(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	pepper := "api-client-test-pepper-with-enough-length"
	expiredAt := time.Now().UTC().Add(-time.Minute)

	created, err := CreateAPIClient(ctx, store, pepper, APIClientCreate{
		Name:      "integration",
		Scopes:    []string{"secret:create"},
		ExpiresAt: &expiredAt,
	})
	if err != nil {
		t.Fatalf("create api client failed: %v", err)
	}
	if created.ClientSecret == "" || created.ClientID == "" {
		t.Fatalf("client credentials were not generated: %#v", created)
	}
	stored, err := store.APIClientByClientID(ctx, created.ClientID)
	if err != nil {
		t.Fatalf("lookup api client failed: %v", err)
	}
	if stored.SecretHash == created.ClientSecret {
		t.Fatal("plaintext client secret was stored")
	}
	if !VerifyAPIClientSecret(pepper, created.ClientID, created.ClientSecret, stored.SecretHash) {
		t.Fatal("stored client secret hash did not verify")
	}
	if IsAPIClientUsable(stored.APIClient) {
		t.Fatal("expired client was usable")
	}

	newSecret, err := NewAPIClientSecret()
	if err != nil {
		t.Fatalf("new secret generation failed: %v", err)
	}
	rotated, err := store.RotateAPIClientSecret(ctx, created.ID, HashAPIClientSecret(pepper, created.ClientID, newSecret))
	if err != nil {
		t.Fatalf("rotate api client failed: %v", err)
	}
	if rotated.Status != APIClientStatusActive {
		t.Fatalf("rotated status = %s, want active", rotated.Status)
	}
	stored, err = store.APIClientByClientID(ctx, created.ClientID)
	if err != nil {
		t.Fatalf("lookup rotated client failed: %v", err)
	}
	if VerifyAPIClientSecret(pepper, created.ClientID, created.ClientSecret, stored.SecretHash) {
		t.Fatal("old client secret still verified after rotation")
	}
	if !VerifyAPIClientSecret(pepper, created.ClientID, newSecret, stored.SecretHash) {
		t.Fatal("new client secret did not verify after rotation")
	}

	revoked, err := store.SetAPIClientStatus(ctx, created.ID, APIClientStatusRevoked)
	if err != nil {
		t.Fatalf("revoke api client failed: %v", err)
	}
	if IsAPIClientUsable(revoked) {
		t.Fatal("revoked client was usable")
	}
}
