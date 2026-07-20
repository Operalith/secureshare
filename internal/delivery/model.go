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
	Secret             json.RawMessage `json:"secret"`
	ExpiresInSeconds   int64           `json:"expires_in_seconds"`
	Password           *string         `json:"password"`
	MaxFailedAttempts  int             `json:"max_failed_attempts"`
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
}

type ConsumeCandidate struct {
	ID                uuid.UUID
	EncryptedPayload  string
	PasswordHash      *string
	FailedAttempts    int
	MaxFailedAttempts int
}

type PrepareResponse struct {
	MayAttempt       bool `json:"may_attempt"`
	PasswordRequired bool `json:"password_required"`
}

type ConsumeResponse struct {
	Secret json.RawMessage `json:"secret"`
}
