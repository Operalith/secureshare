package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

const TokenBytes = 32

func GenerateToken() (string, error) {
	raw := make([]byte, TokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func TokenHMAC(pepper, token string) ([]byte, error) {
	if pepper == "" {
		return nil, errors.New("token pepper is required")
	}
	if token == "" {
		return nil, errors.New("token is required")
	}
	mac := hmac.New(sha256.New, []byte(pepper))
	_, _ = mac.Write([]byte(token))
	return mac.Sum(nil), nil
}

func ConstantTimeEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}
