package crypto

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	vault "github.com/hashicorp/vault/api"
)

type VaultTransit struct {
	client *vault.Client
	key    string
}

func NewVaultTransit(addr, token, key string) (*VaultTransit, error) {
	cfg := vault.DefaultConfig()
	cfg.Address = addr
	client, err := vault.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)
	return &VaultTransit{client: client, key: key}, nil
}

func (v *VaultTransit) Encrypt(ctx context.Context, plaintext []byte) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	secret, err := v.client.Logical().WriteWithContext(ctx, "transit/encrypt/"+v.key, map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	})
	if err != nil {
		return "", err
	}
	if secret == nil || secret.Data == nil {
		return "", errors.New("vault encryption returned no data")
	}
	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok || ciphertext == "" {
		return "", errors.New("vault encryption returned no ciphertext")
	}
	return ciphertext, nil
}

func (v *VaultTransit) Decrypt(ctx context.Context, ciphertext string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	secret, err := v.client.Logical().WriteWithContext(ctx, "transit/decrypt/"+v.key, map[string]interface{}{
		"ciphertext": ciphertext,
	})
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New("vault decryption returned no data")
	}
	encoded, ok := secret.Data["plaintext"].(string)
	if !ok || encoded == "" {
		return nil, errors.New("vault decryption returned no plaintext")
	}
	plaintext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("vault plaintext was not valid base64: %w", err)
	}
	return plaintext, nil
}

func (v *VaultTransit) Ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	health, err := v.client.Sys().HealthWithContext(ctx)
	if err != nil {
		return err
	}
	if health == nil || !health.Initialized || health.Sealed {
		return errors.New("vault is not initialized and unsealed")
	}
	secret, err := v.client.Logical().ReadWithContext(ctx, "transit/keys/"+v.key)
	if err != nil {
		return err
	}
	if secret == nil {
		return errors.New("vault transit key is missing")
	}
	return nil
}
