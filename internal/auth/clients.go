package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	APIClientStatusActive   = "active"
	APIClientStatusDisabled = "disabled"
	APIClientStatusRevoked  = "revoked"
)

var allowedAPIScopeList = []string{
	"secret:create",
	"secret:list",
	"secret:read-metadata",
	"secret:revoke",
	"dashboard:read",
}

var allowedAPIScopes = map[string]bool{
	"secret:create":        true,
	"secret:list":          true,
	"secret:read-metadata": true,
	"secret:revoke":        true,
	"dashboard:read":       true,
}

type APIClient struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	ClientID    string     `json:"client_id"`
	OwnerUserID *uuid.UUID `json:"owner_user_id,omitempty"`
	Status      string     `json:"status"`
	Scopes      []string   `json:"scopes"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type APIClientWithSecret struct {
	APIClient
	SecretHash string
}

type APIClientCreate struct {
	Name        string
	OwnerUserID *uuid.UUID
	Scopes      []string
	ExpiresAt   *time.Time
}

type APIClientCreateResult struct {
	APIClient
	ClientSecret string `json:"client_secret"`
}

type APIClientStore interface {
	CreateAPIClient(context.Context, APIClientCreate, string, string) (APIClient, error)
	ListAPIClients(context.Context) ([]APIClient, error)
	APIClientByID(context.Context, uuid.UUID) (APIClient, error)
	APIClientByClientID(context.Context, string) (APIClientWithSecret, error)
	SetAPIClientStatus(context.Context, uuid.UUID, string) (APIClient, error)
	RotateAPIClientSecret(context.Context, uuid.UUID, string) (APIClient, error)
	TouchAPIClient(context.Context, uuid.UUID) error
}

func AllowedAPIScopes() []string {
	return append([]string(nil), allowedAPIScopeList...)
}

func NormalizeScopes(scopes []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if !allowedAPIScopes[scope] {
			return nil, errors.New("invalid scope")
		}
		if !seen[scope] {
			seen[scope] = true
			out = append(out, scope)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one scope is required")
	}
	return out, nil
}

func NewAPIClientSecret() (string, error) {
	secret, err := GenerateToken(32)
	if err != nil {
		return "", err
	}
	return "sscs_" + secret, nil
}

func NewAPIClientID() (string, error) {
	id, err := GenerateToken(16)
	if err != nil {
		return "", err
	}
	return "ssc_" + id, nil
}

func HashAPIClientSecret(pepper, clientID, secret string) string {
	mac := hmac.New(sha256.New, []byte(pepper))
	_, _ = mac.Write([]byte("api-client:"))
	_, _ = mac.Write([]byte(clientID))
	_, _ = mac.Write([]byte(":"))
	_, _ = mac.Write([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func VerifyAPIClientSecret(pepper, clientID, secret, encoded string) bool {
	expected := HashAPIClientSecret(pepper, clientID, secret)
	return hmac.Equal([]byte(expected), []byte(encoded))
}

func CreateAPIClient(ctx context.Context, store APIClientStore, pepper string, params APIClientCreate) (APIClientCreateResult, error) {
	scopes, err := NormalizeScopes(params.Scopes)
	if err != nil {
		return APIClientCreateResult{}, err
	}
	params.Scopes = scopes
	clientID, err := NewAPIClientID()
	if err != nil {
		return APIClientCreateResult{}, err
	}
	secret, err := NewAPIClientSecret()
	if err != nil {
		return APIClientCreateResult{}, err
	}
	client, err := store.CreateAPIClient(ctx, params, clientID, HashAPIClientSecret(pepper, clientID, secret))
	if err != nil {
		return APIClientCreateResult{}, err
	}
	return APIClientCreateResult{APIClient: client, ClientSecret: secret}, nil
}

func (r *Repository) CreateAPIClient(ctx context.Context, params APIClientCreate, clientID, secretHash string) (APIClient, error) {
	name := strings.TrimSpace(params.Name)
	if name == "" || len(name) > 255 {
		return APIClient{}, errors.New("invalid client name")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	id, err := uuid.NewRandom()
	if err != nil {
		return APIClient{}, err
	}
	var client APIClient
	err = r.db.QueryRow(ctx, `
		INSERT INTO api_clients (id, name, client_id, client_secret_hash, owner_user_id, status, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $5, 'active', $6, $7)
		RETURNING id, name, client_id, owner_user_id, status, scopes, last_used_at, expires_at, created_at, updated_at
	`, id, name, clientID, secretHash, params.OwnerUserID, params.Scopes, params.ExpiresAt).Scan(
		&client.ID, &client.Name, &client.ClientID, &client.OwnerUserID, &client.Status, &client.Scopes,
		&client.LastUsedAt, &client.ExpiresAt, &client.CreatedAt, &client.UpdatedAt,
	)
	return client, err
}

func (r *Repository) ListAPIClients(ctx context.Context) ([]APIClient, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := r.db.Query(ctx, `
		SELECT id, name, client_id, owner_user_id, status, scopes, last_used_at, expires_at, created_at, updated_at
		FROM api_clients ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var clients []APIClient
	for rows.Next() {
		var client APIClient
		if err := rows.Scan(&client.ID, &client.Name, &client.ClientID, &client.OwnerUserID, &client.Status,
			&client.Scopes, &client.LastUsedAt, &client.ExpiresAt, &client.CreatedAt, &client.UpdatedAt); err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	return clients, rows.Err()
}

func (r *Repository) APIClientByID(ctx context.Context, id uuid.UUID) (APIClient, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var client APIClient
	err := r.db.QueryRow(ctx, `
		SELECT id, name, client_id, owner_user_id, status, scopes, last_used_at, expires_at, created_at, updated_at
		FROM api_clients WHERE id = $1
	`, id).Scan(&client.ID, &client.Name, &client.ClientID, &client.OwnerUserID, &client.Status,
		&client.Scopes, &client.LastUsedAt, &client.ExpiresAt, &client.CreatedAt, &client.UpdatedAt)
	return client, err
}

func (r *Repository) APIClientByClientID(ctx context.Context, clientID string) (APIClientWithSecret, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var client APIClientWithSecret
	err := r.db.QueryRow(ctx, `
		SELECT id, name, client_id, client_secret_hash, owner_user_id, status, scopes, last_used_at, expires_at, created_at, updated_at
		FROM api_clients WHERE client_id = $1
	`, clientID).Scan(&client.ID, &client.Name, &client.ClientID, &client.SecretHash, &client.OwnerUserID,
		&client.Status, &client.Scopes, &client.LastUsedAt, &client.ExpiresAt, &client.CreatedAt, &client.UpdatedAt)
	return client, err
}

func (r *Repository) SetAPIClientStatus(ctx context.Context, id uuid.UUID, status string) (APIClient, error) {
	if status != APIClientStatusActive && status != APIClientStatusDisabled && status != APIClientStatusRevoked {
		return APIClient{}, errors.New("invalid client status")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var client APIClient
	err := r.db.QueryRow(ctx, `
		UPDATE api_clients SET status = $2 WHERE id = $1
		RETURNING id, name, client_id, owner_user_id, status, scopes, last_used_at, expires_at, created_at, updated_at
	`, id, status).Scan(&client.ID, &client.Name, &client.ClientID, &client.OwnerUserID, &client.Status,
		&client.Scopes, &client.LastUsedAt, &client.ExpiresAt, &client.CreatedAt, &client.UpdatedAt)
	return client, err
}

func (r *Repository) RotateAPIClientSecret(ctx context.Context, id uuid.UUID, secretHash string) (APIClient, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var client APIClient
	err := r.db.QueryRow(ctx, `
		UPDATE api_clients SET client_secret_hash = $2, status = 'active' WHERE id = $1
		RETURNING id, name, client_id, owner_user_id, status, scopes, last_used_at, expires_at, created_at, updated_at
	`, id, secretHash).Scan(&client.ID, &client.Name, &client.ClientID, &client.OwnerUserID, &client.Status,
		&client.Scopes, &client.LastUsedAt, &client.ExpiresAt, &client.CreatedAt, &client.UpdatedAt)
	return client, err
}

func (r *Repository) TouchAPIClient(ctx context.Context, id uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.db.Exec(ctx, `UPDATE api_clients SET last_used_at = NOW() WHERE id = $1`, id)
	return err
}

func ScopeAllowed(scopes []string, permission string) bool {
	for _, scope := range scopes {
		if scope == permission {
			return true
		}
		if permission == "secret:read-metadata" && scope == "secret:list" {
			return true
		}
	}
	return false
}

func IsAPIClientUsable(client APIClient) bool {
	if client.Status != APIClientStatusActive {
		return false
	}
	return client.ExpiresAt == nil || time.Now().UTC().Before(*client.ExpiresAt)
}

func (m *MemoryStore) CreateAPIClient(_ context.Context, params APIClientCreate, clientID, secretHash string) (APIClient, error) {
	name := strings.TrimSpace(params.Name)
	if name == "" {
		return APIClient{}, errors.New("invalid client name")
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return APIClient{}, err
	}
	now := time.Now().UTC()
	client := APIClientWithSecret{
		APIClient: APIClient{
			ID:          id,
			Name:        name,
			ClientID:    clientID,
			OwnerUserID: params.OwnerUserID,
			Status:      APIClientStatusActive,
			Scopes:      append([]string(nil), params.Scopes...),
			ExpiresAt:   params.ExpiresAt,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		SecretHash: secretHash,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[id] = client
	return client.APIClient, nil
}

func (m *MemoryStore) ListAPIClients(context.Context) ([]APIClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	clients := make([]APIClient, 0, len(m.clients))
	for _, client := range m.clients {
		clients = append(clients, client.APIClient)
	}
	return clients, nil
}

func (m *MemoryStore) APIClientByID(_ context.Context, id uuid.UUID) (APIClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	client, ok := m.clients[id]
	if !ok {
		return APIClient{}, pgx.ErrNoRows
	}
	return client.APIClient, nil
}

func (m *MemoryStore) APIClientByClientID(_ context.Context, clientID string) (APIClientWithSecret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, client := range m.clients {
		if client.ClientID == clientID {
			return client, nil
		}
	}
	return APIClientWithSecret{}, pgx.ErrNoRows
}

func (m *MemoryStore) SetAPIClientStatus(_ context.Context, id uuid.UUID, status string) (APIClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	client, ok := m.clients[id]
	if !ok {
		return APIClient{}, pgx.ErrNoRows
	}
	client.Status = status
	client.UpdatedAt = time.Now().UTC()
	m.clients[id] = client
	return client.APIClient, nil
}

func (m *MemoryStore) RotateAPIClientSecret(_ context.Context, id uuid.UUID, secretHash string) (APIClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	client, ok := m.clients[id]
	if !ok {
		return APIClient{}, pgx.ErrNoRows
	}
	client.SecretHash = secretHash
	client.Status = APIClientStatusActive
	client.UpdatedAt = time.Now().UTC()
	m.clients[id] = client
	return client.APIClient, nil
}

func (m *MemoryStore) TouchAPIClient(_ context.Context, id uuid.UUID) error {
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	client, ok := m.clients[id]
	if !ok {
		return pgx.ErrNoRows
	}
	client.LastUsedAt = &now
	client.UpdatedAt = now
	m.clients[id] = client
	return nil
}
