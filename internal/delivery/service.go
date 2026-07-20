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
	Revoke(context.Context, uuid.UUID) (RevokeResult, error)
	RecordAuditEvent(context.Context, AuditEventRecord) error
	Prepare(context.Context, []byte) (PrepareResponse, error)
	BeginConsume(context.Context, []byte, uuid.UUID, time.Duration) (ConsumeCandidate, bool, error)
	RecordPasswordFailure(context.Context, uuid.UUID, uuid.UUID) error
	RestoreConsume(context.Context, uuid.UUID, uuid.UUID) error
	CompleteConsume(context.Context, uuid.UUID, uuid.UUID) (bool, error)
	Cleanup(context.Context, time.Duration, time.Duration, time.Duration, time.Duration, time.Duration) (CleanupResult, error)
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
	vaultStart := time.Now()
	encrypted, err := s.vault.Encrypt(ctx, req.Secret)
	s.observeVault(vaultStart, "encrypt")
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
	dbStart := time.Now()
	err = s.store.Insert(ctx, InsertParams{
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
	})
	s.observeDatabase(dbStart, "insert_delivery")
	if err != nil {
		return CreateResponse{}, fmt.Errorf("%w: insert delivery failed", ErrInternal)
	}
	s.recordAudit(ctx, AuditEventRecord{DeliveryID: &id, ActorID: actorID, Type: "secret.created", Result: "success"})
	s.metrics.SecretCreated.Inc()
	return CreateResponse{
		ID:        id,
		URL:       s.cfg.AppBaseURL + "/s#" + token,
		Status:    StatusActive,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *Service) Metadata(ctx context.Context, id uuid.UUID) (Metadata, error) {
	start := time.Now()
	result, err := s.store.Metadata(ctx, id)
	s.observeDatabase(start, "metadata")
	return result, err
}

func (s *Service) List(ctx context.Context, opts ListOptions) (ListResult, error) {
	start := time.Now()
	result, err := s.store.List(ctx, opts)
	s.observeDatabase(start, "list")
	return result, err
}

func (s *Service) Dashboard(ctx context.Context) (DashboardStats, error) {
	start := time.Now()
	result, err := s.store.Dashboard(ctx)
	s.observeDatabase(start, "dashboard")
	return result, err
}

func (s *Service) RecentActivity(ctx context.Context, limit int) ([]ActivityEvent, error) {
	start := time.Now()
	result, err := s.store.RecentActivity(ctx, limit)
	s.observeDatabase(start, "recent_activity")
	return result, err
}

func (s *Service) Revoke(ctx context.Context, id uuid.UUID, actorID, ipHash, requestID string) (RevokeResult, error) {
	start := time.Now()
	result, err := s.store.Revoke(ctx, id)
	s.observeDatabase(start, "revoke")
	if err == nil && result.Revoked {
		s.metrics.SecretRevoked.Inc()
	}
	auditResult := "unavailable"
	if result.Found {
		auditResult = result.Status
	}
	s.recordAudit(ctx, AuditEventRecord{DeliveryID: &id, ActorID: actorID, Type: "secret.revoked", Result: auditResult, IPHash: ipHash, RequestID: requestID})
	return result, err
}

func (s *Service) RecordAudit(ctx context.Context, event AuditEventRecord) {
	s.recordAudit(ctx, event)
}

func (s *Service) Cleanup(ctx context.Context) (CleanupResult, error) {
	start := time.Now()
	result, err := s.store.Cleanup(ctx, s.cfg.ConsumedRetention, s.cfg.ExpiredRetention, s.cfg.RevokedRetention, s.cfg.ConsumingLeaseTTL, s.cfg.AuditRetention)
	elapsed := time.Since(start).Seconds()
	s.observeDatabase(start, "cleanup")
	if s.metrics != nil {
		s.metrics.CleanupDuration.Observe(elapsed)
		s.metrics.CleanupDeletions.WithLabelValues("payload").Add(float64(result.PayloadsCleared))
		s.metrics.CleanupDeletions.WithLabelValues("audit").Add(float64(result.AuditDeleted))
		s.metrics.StaleLeaseRecovery.Add(float64(result.LeasesRestored))
	}
	return result, err
}

func (s *Service) Prepare(ctx context.Context, token string) (PrepareResponse, error) {
	tokenHash, err := securecrypto.TokenHMAC(s.cfg.TokenHMACPepper, token)
	if err != nil {
		return PrepareResponse{MayAttempt: false, PasswordRequired: false}, nil
	}
	start := time.Now()
	result, err := s.store.Prepare(ctx, tokenHash)
	s.observeDatabase(start, "prepare")
	return result, err
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

	dbStart := time.Now()
	item, ok, err := s.store.BeginConsume(ctx, tokenHash, leaseID, s.cfg.ConsumingLeaseTTL)
	s.observeDatabase(dbStart, "begin_consume")
	if err != nil {
		return ConsumeResponse{}, fmt.Errorf("%w: begin consume failed", ErrInternal)
	}
	if !ok {
		s.metrics.SecretUnavailable.Inc()
		return ConsumeResponse{}, ErrSecretUnavailable
	}

	if item.PasswordHash != nil && !auth.VerifyPassword(password, *item.PasswordHash) {
		dbStart := time.Now()
		err := s.store.RecordPasswordFailure(ctx, item.ID, leaseID)
		s.observeDatabase(dbStart, "record_password_failure")
		if err != nil {
			s.logger.Warn("password failure state update failed", "delivery_id", item.ID, "error", err)
		}
		s.recordAudit(ctx, AuditEventRecord{DeliveryID: &item.ID, Type: "secret.password_failed", Result: "unavailable"})
		s.metrics.SecretUnavailable.Inc()
		return ConsumeResponse{}, ErrSecretUnavailable
	}

	vaultStart := time.Now()
	plaintext, err := s.vault.Decrypt(ctx, item.EncryptedPayload)
	s.observeVault(vaultStart, "decrypt")
	if err != nil {
		s.metrics.VaultErrors.Inc()
		dbStart := time.Now()
		restoreErr := s.store.RestoreConsume(ctx, item.ID, leaseID)
		s.observeDatabase(dbStart, "restore_consume")
		if restoreErr != nil {
			s.logger.Error("consume restore failed after vault error", "delivery_id", item.ID, "error", restoreErr)
		}
		return ConsumeResponse{}, fmt.Errorf("%w: vault decrypt failed", ErrDependencyUnavailable)
	}

	dbStart = time.Now()
	completed, err := s.store.CompleteConsume(ctx, item.ID, leaseID)
	s.observeDatabase(dbStart, "complete_consume")
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
	s.recordAudit(ctx, AuditEventRecord{DeliveryID: &item.ID, Type: "secret.consumed", Result: "success"})
	s.metrics.SecretConsumed.Inc()
	return ConsumeResponse{Secret: json.RawMessage(plaintext)}, nil
}

func (s *Service) recordAudit(ctx context.Context, event AuditEventRecord) {
	if event.Result == "" {
		event.Result = "success"
	}
	start := time.Now()
	err := s.store.RecordAuditEvent(ctx, event)
	s.observeDatabase(start, "record_audit")
	if err != nil {
		s.logger.Warn("audit event recording failed", "event_type", event.Type, "result", event.Result, "error", err)
	}
}

func (s *Service) observeVault(start time.Time, operation string) {
	if s.metrics == nil {
		return
	}
	s.metrics.VaultDuration.WithLabelValues(operation).Observe(time.Since(start).Seconds())
}

func (s *Service) observeDatabase(start time.Time, operation string) {
	if s.metrics == nil {
		return
	}
	s.metrics.DatabaseDuration.WithLabelValues(operation).Observe(time.Since(start).Seconds())
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
