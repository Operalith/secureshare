package email

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) GetSettings(ctx context.Context) (StoredSettings, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var settings StoredSettings
	err := r.db.QueryRow(ctx, `
		SELECT id, enabled, COALESCE(smtp_host, ''), COALESCE(smtp_port, 0),
			encryption_mode, COALESCE(smtp_username, ''), COALESCE(smtp_password_ciphertext, ''),
			COALESCE(from_name, ''), COALESCE(from_email, ''), COALESCE(reply_to_email, ''),
			connection_timeout_seconds, send_timeout_seconds, default_subject, default_message,
			COALESCE(footer_text, ''), updated_by, created_at, updated_at
		FROM email_settings
		WHERE id = $1
	`, SingletonID).Scan(
		&settings.ID, &settings.Enabled, &settings.SMTPHost, &settings.SMTPPort,
		&settings.EncryptionMode, &settings.SMTPUsername, &settings.SMTPPasswordCiphertext,
		&settings.FromName, &settings.FromEmail, &settings.ReplyToEmail,
		&settings.ConnectionTimeoutSeconds, &settings.SendTimeoutSeconds, &settings.DefaultSubject,
		&settings.DefaultMessage, &settings.FooterText, &settings.UpdatedBy, &settings.CreatedAt, &settings.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return StoredSettings{}, ErrNotConfigured
	}
	if err != nil {
		return StoredSettings{}, err
	}
	settings.PasswordConfigured = settings.SMTPPasswordCiphertext != ""
	return settings, nil
}

func (r *Repository) SaveSettings(ctx context.Context, settings StoredSettings) (StoredSettings, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	normalizeSettings(&settings.Settings)
	settings.ID = SingletonID
	err := r.db.QueryRow(ctx, `
		INSERT INTO email_settings (
			id, enabled, smtp_host, smtp_port, encryption_mode, smtp_username, smtp_password_ciphertext,
			from_name, from_email, reply_to_email, connection_timeout_seconds, send_timeout_seconds,
			default_subject, default_message, footer_text, updated_by
		)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, 0), $5, NULLIF($6, ''), NULLIF($7, ''),
			NULLIF($8, ''), NULLIF($9, ''), NULLIF($10, ''), $11, $12, $13, $14, NULLIF($15, ''), $16)
		ON CONFLICT (id) DO UPDATE
		SET enabled = EXCLUDED.enabled,
			smtp_host = EXCLUDED.smtp_host,
			smtp_port = EXCLUDED.smtp_port,
			encryption_mode = EXCLUDED.encryption_mode,
			smtp_username = EXCLUDED.smtp_username,
			smtp_password_ciphertext = EXCLUDED.smtp_password_ciphertext,
			from_name = EXCLUDED.from_name,
			from_email = EXCLUDED.from_email,
			reply_to_email = EXCLUDED.reply_to_email,
			connection_timeout_seconds = EXCLUDED.connection_timeout_seconds,
			send_timeout_seconds = EXCLUDED.send_timeout_seconds,
			default_subject = EXCLUDED.default_subject,
			default_message = EXCLUDED.default_message,
			footer_text = EXCLUDED.footer_text,
			updated_by = EXCLUDED.updated_by
		RETURNING id, enabled, COALESCE(smtp_host, ''), COALESCE(smtp_port, 0),
			encryption_mode, COALESCE(smtp_username, ''), COALESCE(smtp_password_ciphertext, ''),
			COALESCE(from_name, ''), COALESCE(from_email, ''), COALESCE(reply_to_email, ''),
			connection_timeout_seconds, send_timeout_seconds, default_subject, default_message,
			COALESCE(footer_text, ''), updated_by, created_at, updated_at
	`, settings.ID, settings.Enabled, settings.SMTPHost, settings.SMTPPort, settings.EncryptionMode,
		settings.SMTPUsername, settings.SMTPPasswordCiphertext, settings.FromName, settings.FromEmail,
		settings.ReplyToEmail, settings.ConnectionTimeoutSeconds, settings.SendTimeoutSeconds,
		settings.DefaultSubject, settings.DefaultMessage, settings.FooterText, settings.UpdatedBy).Scan(
		&settings.ID, &settings.Enabled, &settings.SMTPHost, &settings.SMTPPort,
		&settings.EncryptionMode, &settings.SMTPUsername, &settings.SMTPPasswordCiphertext,
		&settings.FromName, &settings.FromEmail, &settings.ReplyToEmail,
		&settings.ConnectionTimeoutSeconds, &settings.SendTimeoutSeconds, &settings.DefaultSubject,
		&settings.DefaultMessage, &settings.FooterText, &settings.UpdatedBy, &settings.CreatedAt, &settings.UpdatedAt,
	)
	if err != nil {
		return StoredSettings{}, err
	}
	settings.PasswordConfigured = settings.SMTPPasswordCiphertext != ""
	return settings, nil
}

type MemoryStore struct {
	mu         sync.Mutex
	settings   StoredSettings
	configured bool
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

func (m *MemoryStore) GetSettings(context.Context) (StoredSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.configured {
		return StoredSettings{}, ErrNotConfigured
	}
	return m.settings, nil
}

func (m *MemoryStore) SaveSettings(_ context.Context, settings StoredSettings) (StoredSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	if !m.configured {
		settings.CreatedAt = now
	}
	settings.UpdatedAt = now
	settings.ID = SingletonID
	settings.PasswordConfigured = settings.SMTPPasswordCiphertext != ""
	m.settings = settings
	m.configured = true
	return m.settings, nil
}

func (m *MemoryStore) StoredForTest() StoredSettings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settings
}

var _ Store = (*Repository)(nil)
var _ Store = (*MemoryStore)(nil)
