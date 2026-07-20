package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"secureshare/internal/auth"
	"secureshare/internal/config"
	securecrypto "secureshare/internal/crypto"
	"secureshare/internal/observability"
)

type Vault interface {
	Encrypt(context.Context, []byte) (string, error)
	Decrypt(context.Context, string) ([]byte, error)
	Ready(context.Context) error
}

type Store interface {
	Insert(context.Context, InsertParams) error
	Metadata(context.Context, uuid.UUID) (Metadata, error)
	List(context.Context, ListOptions) (ListResult, error)
	Dashboard(context.Context) (DashboardStats, error)
	RecentActivity(context.Context, int) ([]ActivityEvent, error)
	Revoke(context.Context, uuid.UUID) (bool, error)
	Prepare(context.Context, []byte) (PrepareResponse, error)
	BeginConsume(context.Context, []byte, uuid.UUID, time.Duration) (ConsumeCandidate, bool, error)
	RecordPasswordFailure(context.Context, uuid.UUID, uuid.UUID) error
	RestoreConsume(context.Context, uuid.UUID, uuid.UUID) error
	CompleteConsume(context.Context, uuid.UUID, uuid.UUID) (bool, error)
	CountActive(context.Context) (float64, error)
}

type Service struct {
	cfg     config.Config
	store   Store
	vault   Vault
	metrics *observability.Metrics
	logger  *slog.Logger
}

func NewService(cfg config.Config, store Store, vault Vault, metrics *observability.Metrics, logger *slog.Logger) *Service {
	return &Service{cfg: cfg, store: store, vault: vault, metrics: metrics, logger: logger}
}

func (s *Service) Create(ctx context.Context, actorID string, req CreateRequest) (CreateResponse, error) {
	if actorID == "" {
		return CreateResponse{}, ErrUnauthorized
	}
	if err := s.validateCreate(req); err != nil {
		return CreateResponse{}, err
	}

	token, err := securecrypto.GenerateToken()
	if err != nil {
		return CreateResponse{}, fmt.Errorf("%w: token generation failed", ErrInternal)
	}
	tokenHash, err := securecrypto.TokenHMAC(s.cfg.TokenHMACPepper, token)
	if err != nil {
		return CreateResponse{}, fmt.Errorf("%w: token hash failed", ErrInternal)
	}
	encrypted, err := s.vault.Encrypt(ctx, req.Secret)
	if err != nil {
		s.metrics.VaultErrors.Inc()
		return CreateResponse{}, fmt.Errorf("%w: vault encrypt failed", ErrDependencyUnavailable)
	}

	var passwordHash *string
	if req.Password != nil && strings.TrimSpace(*req.Password) != "" {
		hash, err := auth.HashPassword(*req.Password)
		if err != nil {
			return CreateResponse{}, fmt.Errorf("%w: password hash failed", ErrInternal)
		}
		passwordHash = &hash
	}

	ttl := s.ttl(req.ExpiresInSeconds)
	expiresAt := time.Now().UTC().Add(ttl)
	maxFailed := req.MaxFailedAttempts
	if maxFailed <= 0 {
		maxFailed = 5
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return CreateResponse{}, fmt.Errorf("%w: id generation failed", ErrInternal)
	}
	if err := s.store.Insert(ctx, InsertParams{
		ID:                 id,
		TokenHash:          tokenHash,
		EncryptedPayload:   encrypted,
		Title:              strings.TrimSpace(req.Title),
		Description:        strings.TrimSpace(req.Description),
		RecipientReference: strings.TrimSpace(req.RecipientReference),
		Status:             StatusActive,
		ExpiresAt:          expiresAt,
		PasswordHash:       passwordHash,
		MaxFailedAttempts:  maxFailed,
		CreatedBy:          actorID,
	}); err != nil {
		return CreateResponse{}, fmt.Errorf("%w: insert delivery failed", ErrInternal)
	}
	s.metrics.SecretCreated.Inc()
	return CreateResponse{
		ID:        id,
		URL:       s.cfg.AppBaseURL + "/s#" + token,
		Status:    StatusActive,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *Service) Metadata(ctx context.Context, id uuid.UUID) (Metadata, error) {
	return s.store.Metadata(ctx, id)
}

func (s *Service) List(ctx context.Context, opts ListOptions) (ListResult, error) {
	return s.store.List(ctx, opts)
}

func (s *Service) Dashboard(ctx context.Context) (DashboardStats, error) {
	return s.store.Dashboard(ctx)
}

func (s *Service) RecentActivity(ctx context.Context, limit int) ([]ActivityEvent, error) {
	return s.store.RecentActivity(ctx, limit)
}

func (s *Service) Revoke(ctx context.Context, id uuid.UUID) (bool, error) {
	ok, err := s.store.Revoke(ctx, id)
	if err == nil && ok {
		s.metrics.SecretRevoked.Inc()
	}
	return ok, err
}

func (s *Service) Prepare(ctx context.Context, token string) (PrepareResponse, error) {
	tokenHash, err := securecrypto.TokenHMAC(s.cfg.TokenHMACPepper, token)
	if err != nil {
		return PrepareResponse{MayAttempt: false, PasswordRequired: false}, nil
	}
	return s.store.Prepare(ctx, tokenHash)
}

func (s *Service) Consume(ctx context.Context, token string, password string) (ConsumeResponse, error) {
	start := time.Now()
	defer func() {
		s.metrics.ConsumeDuration.Observe(time.Since(start).Seconds())
	}()

	tokenHash, err := securecrypto.TokenHMAC(s.cfg.TokenHMACPepper, token)
	if err != nil {
		s.metrics.SecretUnavailable.Inc()
		return ConsumeResponse{}, ErrSecretUnavailable
	}
	leaseID, err := uuid.NewRandom()
	if err != nil {
		return ConsumeResponse{}, fmt.Errorf("%w: lease id failed", ErrInternal)
	}

	item, ok, err := s.store.BeginConsume(ctx, tokenHash, leaseID, s.cfg.ConsumingLeaseTTL)
	if err != nil {
		return ConsumeResponse{}, fmt.Errorf("%w: begin consume failed", ErrInternal)
	}
	if !ok {
		s.metrics.SecretUnavailable.Inc()
		return ConsumeResponse{}, ErrSecretUnavailable
	}

	if item.PasswordHash != nil && !auth.VerifyPassword(password, *item.PasswordHash) {
		if err := s.store.RecordPasswordFailure(ctx, item.ID, leaseID); err != nil {
			s.logger.Warn("password failure state update failed", "delivery_id", item.ID, "error", err)
		}
		s.metrics.SecretUnavailable.Inc()
		return ConsumeResponse{}, ErrSecretUnavailable
	}

	plaintext, err := s.vault.Decrypt(ctx, item.EncryptedPayload)
	if err != nil {
		s.metrics.VaultErrors.Inc()
		if restoreErr := s.store.RestoreConsume(ctx, item.ID, leaseID); restoreErr != nil {
			s.logger.Error("consume restore failed after vault error", "delivery_id", item.ID, "error", restoreErr)
		}
		return ConsumeResponse{}, fmt.Errorf("%w: vault decrypt failed", ErrDependencyUnavailable)
	}

	completed, err := s.store.CompleteConsume(ctx, item.ID, leaseID)
	if err != nil {
		return ConsumeResponse{}, fmt.Errorf("%w: complete consume failed", ErrInternal)
	}
	if !completed {
		s.metrics.SecretUnavailable.Inc()
		return ConsumeResponse{}, ErrSecretUnavailable
	}
	if !json.Valid(plaintext) {
		return ConsumeResponse{}, fmt.Errorf("%w: decrypted payload was invalid", ErrInternal)
	}
	s.metrics.SecretConsumed.Inc()
	return ConsumeResponse{Secret: json.RawMessage(plaintext)}, nil
}

func (s *Service) validateCreate(req CreateRequest) error {
	if len(req.Secret) == 0 || string(req.Secret) == "null" {
		return ErrInvalidRequest
	}
	if !json.Valid(req.Secret) {
		return ErrInvalidRequest
	}
	if int64(len(req.Secret)) > s.cfg.MaxSecretBytes {
		return ErrPayloadTooLarge
	}
	if len(req.Title) > 255 || len(req.Description) > 2000 || len(req.RecipientReference) > 255 {
		return ErrInvalidRequest
	}
	if req.MaxFailedAttempts < 0 || req.MaxFailedAttempts > 20 {
		return ErrInvalidRequest
	}
	if req.ExpiresInSeconds > 0 && time.Duration(req.ExpiresInSeconds)*time.Second > s.cfg.MaxSecretTTL {
		return ErrInvalidRequest
	}
	return nil
}

func (s *Service) ttl(seconds int64) time.Duration {
	if seconds <= 0 {
		return s.cfg.DefaultSecretTTL
	}
	return time.Duration(seconds) * time.Second
}

func ErrorStatus(err error) int {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return 401
	case errors.Is(err, ErrForbidden):
		return 403
	case errors.Is(err, ErrSecretUnavailable):
		return 410
	case errors.Is(err, ErrPayloadTooLarge):
		return 413
	case errors.Is(err, ErrDependencyUnavailable):
		return 503
	case errors.Is(err, ErrInvalidRequest):
		return 400
	default:
		return 500
	}
}

func ErrorCodeFor(err error) ErrorCode {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return CodeUnauthorized
	case errors.Is(err, ErrForbidden):
		return CodeForbidden
	case errors.Is(err, ErrSecretUnavailable):
		return CodeSecretUnavailable
	case errors.Is(err, ErrPayloadTooLarge):
		return CodePayloadTooLarge
	case errors.Is(err, ErrDependencyUnavailable):
		return CodeDependencyUnavailable
	case errors.Is(err, ErrInvalidRequest):
		return CodeInvalidRequest
	default:
		return CodeInternal
	}
}
