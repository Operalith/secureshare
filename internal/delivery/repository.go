package delivery

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Insert(ctx context.Context, params InsertParams) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.db.Exec(ctx, `
		INSERT INTO secret_deliveries (
			id, token_hash, encrypted_payload, title, description, recipient_reference,
			status, expires_at, password_hash, max_failed_attempts, created_by
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`, params.ID, params.TokenHash, params.EncryptedPayload, emptyToNil(params.Title),
		emptyToNil(params.Description), emptyToNil(params.RecipientReference), params.Status,
		params.ExpiresAt, params.PasswordHash, params.MaxFailedAttempts, params.CreatedBy)
	return err
}

func (r *Repository) Metadata(ctx context.Context, id uuid.UUID) (Metadata, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var item Metadata
	err := r.db.QueryRow(ctx, `
		SELECT id, COALESCE(title,''), COALESCE(description,''), COALESCE(recipient_reference,''),
			status, expires_at, consumed_at, revoked_at, created_by, created_at, updated_at,
			password_hash IS NOT NULL, failed_attempts, max_failed_attempts
		FROM secret_deliveries
		WHERE id = $1
	`, id).Scan(&item.ID, &item.Title, &item.Description, &item.RecipientReference,
		&item.Status, &item.ExpiresAt, &item.ConsumedAt, &item.RevokedAt, &item.CreatedBy,
		&item.CreatedAt, &item.UpdatedAt, &item.PasswordProtected, &item.FailedAttempts, &item.MaxFailedAttempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return Metadata{}, ErrSecretUnavailable
	}
	return item, err
}

func (r *Repository) Revoke(ctx context.Context, id uuid.UUID) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tag, err := r.db.Exec(ctx, `
		UPDATE secret_deliveries
		SET status = 'revoked',
			revoked_at = NOW(),
			encrypted_payload = '',
			consuming_started_at = NULL,
			consuming_lease_id = NULL,
			updated_at = NOW()
		WHERE id = $1
		  AND status IN ('active', 'consuming')
	`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (r *Repository) Prepare(ctx context.Context, tokenHash []byte) (PrepareResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var response PrepareResponse
	err := r.db.QueryRow(ctx, `
		SELECT TRUE, password_hash IS NOT NULL
		FROM secret_deliveries
		WHERE token_hash = $1
		  AND status = 'active'
		  AND expires_at > NOW()
		  AND failed_attempts < max_failed_attempts
	`, tokenHash).Scan(&response.MayAttempt, &response.PasswordRequired)
	if errors.Is(err, pgx.ErrNoRows) {
		return PrepareResponse{MayAttempt: false, PasswordRequired: false}, nil
	}
	return response, err
}

func (r *Repository) BeginConsume(ctx context.Context, tokenHash []byte, leaseID uuid.UUID, leaseTTL time.Duration) (ConsumeCandidate, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	leaseSeconds := int64(leaseTTL.Seconds())
	var item ConsumeCandidate
	err := r.db.QueryRow(ctx, `
		UPDATE secret_deliveries
		SET status = 'consuming',
			consuming_started_at = NOW(),
			consuming_lease_id = $2,
			updated_at = NOW()
		WHERE token_hash = $1
		  AND expires_at > NOW()
		  AND failed_attempts < max_failed_attempts
		  AND (
			status = 'active'
			OR (status = 'consuming' AND consuming_started_at < NOW() - make_interval(secs => $3))
		  )
		RETURNING id, encrypted_payload, password_hash, failed_attempts, max_failed_attempts
	`, tokenHash, leaseID, leaseSeconds).Scan(&item.ID, &item.EncryptedPayload, &item.PasswordHash, &item.FailedAttempts, &item.MaxFailedAttempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConsumeCandidate{}, false, nil
	}
	return item, true, err
}

func (r *Repository) RecordPasswordFailure(ctx context.Context, id uuid.UUID, leaseID uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.db.Exec(ctx, `
		UPDATE secret_deliveries
		SET failed_attempts = failed_attempts + 1,
			status = CASE WHEN failed_attempts + 1 >= max_failed_attempts THEN 'revoked' ELSE 'active' END,
			revoked_at = CASE WHEN failed_attempts + 1 >= max_failed_attempts THEN NOW() ELSE revoked_at END,
			encrypted_payload = CASE WHEN failed_attempts + 1 >= max_failed_attempts THEN '' ELSE encrypted_payload END,
			consuming_started_at = NULL,
			consuming_lease_id = NULL,
			updated_at = NOW()
		WHERE id = $1
		  AND status = 'consuming'
		  AND consuming_lease_id = $2
	`, id, leaseID)
	return err
}

func (r *Repository) RestoreConsume(ctx context.Context, id uuid.UUID, leaseID uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.db.Exec(ctx, `
		UPDATE secret_deliveries
		SET status = 'active',
			consuming_started_at = NULL,
			consuming_lease_id = NULL,
			updated_at = NOW()
		WHERE id = $1
		  AND status = 'consuming'
		  AND consuming_lease_id = $2
	`, id, leaseID)
	return err
}

func (r *Repository) CompleteConsume(ctx context.Context, id uuid.UUID, leaseID uuid.UUID) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tag, err := r.db.Exec(ctx, `
		UPDATE secret_deliveries
		SET status = 'consumed',
			consumed_at = NOW(),
			encrypted_payload = '',
			consuming_started_at = NULL,
			consuming_lease_id = NULL,
			updated_at = NOW()
		WHERE id = $1
		  AND status = 'consuming'
		  AND consuming_lease_id = $2
	`, id, leaseID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (r *Repository) Cleanup(ctx context.Context, consumedRetention, expiredRetention, revokedRetention, leaseTTL time.Duration) (expired int64, cleared int64, restored int64, err error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	leaseSeconds := int64(leaseTTL.Seconds())

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
		}
	}()

	tag, err := tx.Exec(ctx, `
		UPDATE secret_deliveries
		SET status = 'expired',
			updated_at = NOW()
		WHERE status = 'active'
		  AND expires_at <= NOW()
	`)
	if err != nil {
		return 0, 0, 0, err
	}
	expired = tag.RowsAffected()

	tag, err = tx.Exec(ctx, `
		UPDATE secret_deliveries
		SET status = 'active',
			consuming_started_at = NULL,
			consuming_lease_id = NULL,
			updated_at = NOW()
		WHERE status = 'consuming'
		  AND consuming_started_at < NOW() - make_interval(secs => $1)
		  AND expires_at > NOW()
	`, leaseSeconds)
	if err != nil {
		return 0, 0, 0, err
	}
	restored = tag.RowsAffected()

	tag, err = tx.Exec(ctx, `
		UPDATE secret_deliveries
		SET encrypted_payload = '',
			updated_at = NOW()
		WHERE encrypted_payload <> ''
		  AND (
			(status = 'consumed' AND consumed_at IS NOT NULL AND consumed_at <= NOW() - make_interval(secs => $1))
			OR (status = 'expired' AND updated_at <= NOW() - make_interval(secs => $2))
			OR (status = 'revoked' AND revoked_at IS NOT NULL AND revoked_at <= NOW() - make_interval(secs => $3))
		  )
	`, int64(consumedRetention.Seconds()), int64(expiredRetention.Seconds()), int64(revokedRetention.Seconds()))
	if err != nil {
		return 0, 0, 0, err
	}
	cleared = tag.RowsAffected()

	if err = tx.Commit(ctx); err != nil {
		return 0, 0, 0, err
	}
	return expired, cleared, restored, nil
}

func (r *Repository) CountActive(ctx context.Context) (float64, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var count float64
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*)::float8
		FROM secret_deliveries
		WHERE status = 'active'
		  AND expires_at > NOW()
	`).Scan(&count)
	return count, err
}

func emptyToNil(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
