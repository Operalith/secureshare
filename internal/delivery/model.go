package delivery

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

const (
	StatusActive    = "active"
	StatusConsuming = "consuming"
	StatusConsumed  = "consumed"
	StatusExpired   = "expired"
	StatusRevoked   = "revoked"
)

type CreateRequest struct {
	Title              string          `json:"title"`
	Description        string          `json:"description"`
	RecipientReference string          `json:"recipient_reference"`
	Secret             json.RawMessage `json:"secret,omitempty"`
	Payload            *SecretPayload  `json:"payload,omitempty"`
	ExpiresInSeconds   int64           `json:"expires_in_seconds"`
	Password           *string         `json:"password"`
	MaxFailedAttempts  int             `json:"max_failed_attempts"`
}

type SecretPayload struct {
	Type   string                  `json:"type"`
	Fields []StructuredSecretField `json:"fields,omitempty"`
	Text   string                  `json:"text,omitempty"`
	Value  json.RawMessage         `json:"value,omitempty"`
}

type StructuredSecretField struct {
	Name      string `json:"name"`
	Label     string `json:"label"`
	Value     string `json:"value"`
	Sensitive bool   `json:"sensitive"`
	Multiline bool   `json:"multiline"`
}

type PayloadSummary struct {
	Type              string `json:"payload_type"`
	FieldCount        int    `json:"payload_field_count"`
	ContainsSensitive bool   `json:"payload_contains_sensitive"`
}

type CreateResponse struct {
	ID        uuid.UUID `json:"id"`
	URL       string    `json:"url"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Metadata struct {
	ID                 uuid.UUID  `json:"id"`
	Title              string     `json:"title,omitempty"`
	Description        string     `json:"description,omitempty"`
	RecipientReference string     `json:"recipient_reference,omitempty"`
	Status             string     `json:"status"`
	ExpiresAt          time.Time  `json:"expires_at"`
	ConsumedAt         *time.Time `json:"consumed_at,omitempty"`
	RevokedAt          *time.Time `json:"revoked_at,omitempty"`
	CreatedBy          string     `json:"created_by"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	PasswordProtected  bool       `json:"password_protected"`
	FailedAttempts     int        `json:"failed_attempts"`
	MaxFailedAttempts  int        `json:"max_failed_attempts"`
	PayloadType        string     `json:"payload_type"`
	PayloadFieldCount  int        `json:"payload_field_count"`
	ContainsSensitive  bool       `json:"payload_contains_sensitive"`
}

type ListOptions struct {
	Page        int
	PageSize    int
	Status      string
	Search      string
	CreatedFrom *time.Time
	CreatedTo   *time.Time
	ExpiresFrom *time.Time
	ExpiresTo   *time.Time
	Sort        string
	Order       string
}

type Pagination struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	TotalItems int `json:"total_items"`
	TotalPages int `json:"total_pages"`
}

type ListResult struct {
	Items      []Metadata `json:"items"`
	Pagination Pagination `json:"pagination"`
}

type DashboardStats struct {
	ActiveCount    int             `json:"active_count"`
	ConsumedCount  int             `json:"consumed_count"`
	ExpiredCount   int             `json:"expired_count"`
	RevokedCount   int             `json:"revoked_count"`
	CreatedToday   int             `json:"created_today"`
	ConsumedToday  int             `json:"consumed_today"`
	RecentActivity []ActivityEvent `json:"recent_activity"`
	Dependencies   DependencyState `json:"dependencies"`
}

type DependencyState struct {
	Postgres          string `json:"postgres"`
	PostgresLatencyMS int64  `json:"postgres_latency_ms"`
	Vault             string `json:"vault"`
	VaultLatencyMS    int64  `json:"vault_latency_ms"`
	CleanupWorker     string `json:"cleanup_worker"`
	CleanupInterval   string `json:"cleanup_interval"`
	LastCleanup       string `json:"last_cleanup"`
	AppVersion        string `json:"app_version"`
}

type ActivityEvent struct {
	EventID            uuid.UUID  `json:"event_id,omitempty"`
	Type               string     `json:"type"`
	DeliveryID         uuid.UUID  `json:"delivery_id"`
	Title              string     `json:"title,omitempty"`
	RecipientReference string     `json:"recipient_reference,omitempty"`
	Status             string     `json:"status"`
	ActorID            string     `json:"actor_id,omitempty"`
	Result             string     `json:"result,omitempty"`
	IPHash             string     `json:"ip_hash,omitempty"`
	RequestID          string     `json:"request_id,omitempty"`
	OccurredAt         time.Time  `json:"occurred_at"`
	ConsumedAt         *time.Time `json:"consumed_at,omitempty"`
	RevokedAt          *time.Time `json:"revoked_at,omitempty"`
}

type AuditEventRecord struct {
	DeliveryID *uuid.UUID
	ActorID    string
	Type       string
	Result     string
	IPHash     string
	RequestID  string
}

type RevokeResult struct {
	ID      uuid.UUID `json:"id"`
	Status  string    `json:"status"`
	Revoked bool      `json:"revoked"`
	Found   bool      `json:"found"`
}

type CleanupResult struct {
	Expired         int64 `json:"expired"`
	PayloadsCleared int64 `json:"payloads_cleared"`
	LeasesRestored  int64 `json:"leases_restored"`
	AuditDeleted    int64 `json:"audit_deleted"`
}

type InsertParams struct {
	ID                 uuid.UUID
	TokenHash          []byte
	EncryptedPayload   string
	Title              string
	Description        string
	RecipientReference string
	Status             string
	ExpiresAt          time.Time
	PasswordHash       *string
	MaxFailedAttempts  int
	CreatedBy          string
	PayloadType        string
	PayloadFieldCount  int
	ContainsSensitive  bool
}

type ConsumeCandidate struct {
	ID                uuid.UUID
	EncryptedPayload  string
	PasswordHash      *string
	FailedAttempts    int
	MaxFailedAttempts int
}

type PrepareResponse struct {
	MayAttempt       bool       `json:"may_attempt"`
	PasswordRequired bool       `json:"password_required"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
}

type ConsumeResponse struct {
	Secret  json.RawMessage `json:"secret"`
	Payload json.RawMessage `json:"payload"`
}
