package email

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	EncryptionStartTLS = "starttls"
	EncryptionTLS      = "tls"
	EncryptionNone     = "none"

	DefaultSubject = "A secure one-time secret has been shared with you"
	DefaultMessage = "Hello {{recipient_name}},\n\nA secure one-time secret has been shared with you through {{product_name}}.\n\nThe secret can only be viewed once and will expire at {{expires_at}}.\n\nOpen the secure secret using the link below:\n\n{{secure_link}}\n\nDo not forward this email or share the link with anyone else.\n\nRegards,\n{{sender_name}}"
)

var (
	SingletonID = uuid.MustParse("00000000-0000-4000-8000-000000000001")

	ErrNotConfigured = errors.New("email settings are not configured")
	ErrInvalid       = errors.New("invalid email settings")
	ErrForbidden     = errors.New("email settings forbidden")
	ErrDependency    = errors.New("email dependency unavailable")
)

type Settings struct {
	ID                       uuid.UUID  `json:"id"`
	Enabled                  bool       `json:"enabled"`
	SMTPHost                 string     `json:"smtp_host,omitempty"`
	SMTPPort                 int        `json:"smtp_port,omitempty"`
	EncryptionMode           string     `json:"encryption_mode"`
	SMTPUsername             string     `json:"smtp_username,omitempty"`
	FromName                 string     `json:"from_name,omitempty"`
	FromEmail                string     `json:"from_email,omitempty"`
	ReplyToEmail             string     `json:"reply_to_email,omitempty"`
	ConnectionTimeoutSeconds int        `json:"connection_timeout_seconds"`
	SendTimeoutSeconds       int        `json:"send_timeout_seconds"`
	DefaultSubject           string     `json:"default_subject"`
	DefaultMessage           string     `json:"default_message"`
	FooterText               string     `json:"footer_text,omitempty"`
	PasswordConfigured       bool       `json:"password_configured"`
	UpdatedBy                *uuid.UUID `json:"updated_by,omitempty"`
	CreatedAt                time.Time  `json:"created_at"`
	UpdatedAt                time.Time  `json:"updated_at"`
}

type StoredSettings struct {
	Settings
	SMTPPasswordCiphertext string
}

type UpdateRequest struct {
	Enabled                  bool   `json:"enabled"`
	SMTPHost                 string `json:"smtp_host"`
	SMTPPort                 int    `json:"smtp_port"`
	EncryptionMode           string `json:"encryption_mode"`
	SMTPUsername             string `json:"smtp_username"`
	SMTPPassword             string `json:"smtp_password"`
	ClearSMTPPassword        bool   `json:"clear_smtp_password"`
	FromName                 string `json:"from_name"`
	FromEmail                string `json:"from_email"`
	ReplyToEmail             string `json:"reply_to_email"`
	ConnectionTimeoutSeconds int    `json:"connection_timeout_seconds"`
	SendTimeoutSeconds       int    `json:"send_timeout_seconds"`
	DefaultSubject           string `json:"default_subject"`
	DefaultMessage           string `json:"default_message"`
	FooterText               string `json:"footer_text"`
}

type UpdateResult struct {
	Settings        Settings
	PasswordUpdated bool
	PasswordCleared bool
}

type ConnectionTestResult struct {
	OK             bool   `json:"ok"`
	Result         string `json:"result"`
	ErrorCategory  string `json:"error_category,omitempty"`
	EncryptionMode string `json:"encryption_mode"`
	DurationMS     int64  `json:"duration_ms"`
}

type SendTestRequest struct {
	To string `json:"to"`
}

type SendRenderedRequest struct {
	To       string
	Rendered RenderedTemplate
}

type Store interface {
	GetSettings(ctx context.Context) (StoredSettings, error)
	SaveSettings(ctx context.Context, settings StoredSettings) (StoredSettings, error)
}
