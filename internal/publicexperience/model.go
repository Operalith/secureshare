package publicexperience

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	LocaleEnglish = "en"
	LocalePersian = "fa"
)

var (
	SingletonID      = uuid.MustParse("00000000-0000-4000-8000-000000000002")
	ErrNotConfigured = errors.New("public experience settings are not configured")
	ErrInvalidLocale = errors.New("public locale must be en or fa")
)

type Settings struct {
	ID           uuid.UUID  `json:"id"`
	PublicLocale string     `json:"public_locale"`
	UpdatedBy    *uuid.UUID `json:"updated_by,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type Store interface {
	GetSettings(context.Context) (Settings, error)
	SaveSettings(context.Context, Settings) (Settings, error)
}

type Service struct {
	store Store
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

func NormalizeLocale(locale string) string {
	locale = strings.ToLower(strings.TrimSpace(locale))
	if locale == LocalePersian {
		return LocalePersian
	}
	return LocaleEnglish
}

func ValidLocale(locale string) bool {
	return locale == LocaleEnglish || locale == LocalePersian
}

func DefaultSettings() Settings {
	return Settings{ID: SingletonID, PublicLocale: LocaleEnglish}
}

func (s *Service) Current(ctx context.Context) (Settings, error) {
	settings, err := s.store.GetSettings(ctx)
	if errors.Is(err, ErrNotConfigured) {
		return DefaultSettings(), nil
	}
	if err != nil {
		return Settings{}, err
	}
	settings.PublicLocale = NormalizeLocale(settings.PublicLocale)
	return settings, nil
}

func (s *Service) Update(ctx context.Context, updatedBy uuid.UUID, locale string) (Settings, error) {
	locale = strings.ToLower(strings.TrimSpace(locale))
	if !ValidLocale(locale) {
		return Settings{}, ErrInvalidLocale
	}
	settings, err := s.Current(ctx)
	if err != nil {
		return Settings{}, err
	}
	settings.ID = SingletonID
	settings.PublicLocale = locale
	settings.UpdatedBy = &updatedBy
	return s.store.SaveSettings(ctx, settings)
}
