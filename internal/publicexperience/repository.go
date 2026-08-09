package publicexperience

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

func (r *Repository) GetSettings(ctx context.Context) (Settings, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var settings Settings
	err := r.db.QueryRow(ctx, `
		SELECT id, public_locale, updated_by, created_at, updated_at
		FROM application_settings
		WHERE id = $1
	`, SingletonID).Scan(&settings.ID, &settings.PublicLocale, &settings.UpdatedBy, &settings.CreatedAt, &settings.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Settings{}, ErrNotConfigured
	}
	return settings, err
}

func (r *Repository) SaveSettings(ctx context.Context, settings Settings) (Settings, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	settings.ID = SingletonID
	err := r.db.QueryRow(ctx, `
		INSERT INTO application_settings (id, public_locale, updated_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (id) DO UPDATE
		SET public_locale = EXCLUDED.public_locale,
			updated_by = EXCLUDED.updated_by
		RETURNING id, public_locale, updated_by, created_at, updated_at
	`, settings.ID, settings.PublicLocale, settings.UpdatedBy).Scan(
		&settings.ID, &settings.PublicLocale, &settings.UpdatedBy, &settings.CreatedAt, &settings.UpdatedAt,
	)
	return settings, err
}

type MemoryStore struct {
	mu       sync.Mutex
	settings Settings
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{settings: DefaultSettings()}
}

func (m *MemoryStore) GetSettings(context.Context) (Settings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settings, nil
}

func (m *MemoryStore) SaveSettings(_ context.Context, settings Settings) (Settings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	if m.settings.CreatedAt.IsZero() {
		settings.CreatedAt = now
	} else {
		settings.CreatedAt = m.settings.CreatedAt
	}
	settings.ID = SingletonID
	settings.UpdatedAt = now
	m.settings = settings
	return m.settings, nil
}

var _ Store = (*Repository)(nil)
var _ Store = (*MemoryStore)(nil)
