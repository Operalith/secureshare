package delivery

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
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

func (r *Repository) List(ctx context.Context, opts ListOptions) (ListResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	opts = normalizeListOptions(opts)
	where, args := listWhere(opts)
	countSQL := "SELECT COUNT(*) FROM secret_deliveries " + where

	var total int
	if err := r.db.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return ListResult{}, err
	}

	sortColumn := map[string]string{
		"created_at": "created_at",
		"expires_at": "expires_at",
	}[opts.Sort]
	order := "DESC"
	if opts.Order == "asc" {
		order = "ASC"
	}
	offset := (opts.Page - 1) * opts.PageSize
	queryArgs := append(args, opts.PageSize, offset)
	rows, err := r.db.Query(ctx, fmt.Sprintf(`
		SELECT id, COALESCE(title,''), COALESCE(description,''), COALESCE(recipient_reference,''),
			status, expires_at, consumed_at, revoked_at, created_by, created_at, updated_at,
			password_hash IS NOT NULL, failed_attempts, max_failed_attempts
		FROM secret_deliveries
		%s
		ORDER BY %s %s, id DESC
		LIMIT $%d OFFSET $%d
	`, where, sortColumn, order, len(queryArgs)-1, len(queryArgs)), queryArgs...)
	if err != nil {
		return ListResult{}, err
	}
	defer rows.Close()

	items := []Metadata{}
	for rows.Next() {
		var item Metadata
		if err := rows.Scan(&item.ID, &item.Title, &item.Description, &item.RecipientReference,
			&item.Status, &item.ExpiresAt, &item.ConsumedAt, &item.RevokedAt, &item.CreatedBy,
			&item.CreatedAt, &item.UpdatedAt, &item.PasswordProtected, &item.FailedAttempts, &item.MaxFailedAttempts); err != nil {
			return ListResult{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return ListResult{}, err
	}

	totalPages := int(math.Ceil(float64(total) / float64(opts.PageSize)))
	if total == 0 {
		totalPages = 0
	}
	return ListResult{
		Items: items,
		Pagination: Pagination{
			Page:       opts.Page,
			PageSize:   opts.PageSize,
			TotalItems: total,
			TotalPages: totalPages,
		},
	}, nil
}

func (r *Repository) Dashboard(ctx context.Context) (DashboardStats, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var stats DashboardStats
	rows, err := r.db.Query(ctx, `
		SELECT status, COUNT(*)
		FROM secret_deliveries
		GROUP BY status
	`)
	if err != nil {
		return stats, err
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return stats, err
		}
		switch status {
		case StatusActive, StatusConsuming:
			stats.ActiveCount += count
		case StatusConsumed:
			stats.ConsumedCount = count
		case StatusExpired:
			stats.ExpiredCount = count
		case StatusRevoked:
			stats.RevokedCount = count
		}
	}
	if err := rows.Err(); err != nil {
		return stats, err
	}

	if err := r.db.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE created_at >= date_trunc('day', NOW())),
			COUNT(*) FILTER (WHERE consumed_at >= date_trunc('day', NOW()))
		FROM secret_deliveries
	`).Scan(&stats.CreatedToday, &stats.ConsumedToday); err != nil {
		return stats, err
	}

	stats.RecentActivity, err = r.RecentActivity(ctx, 8)
	if err != nil {
		return stats, err
	}
	return stats, nil
}

func (r *Repository) RecentActivity(ctx context.Context, limit int) ([]ActivityEvent, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if limit <= 0 || limit > 50 {
		limit = 8
	}
	rows, err := r.db.Query(ctx, `
		SELECT event_type, id, COALESCE(title,''), COALESCE(recipient_reference,''), status, created_by, occurred_at, consumed_at, revoked_at
		FROM (
			SELECT 'secret.created' AS event_type, id, title, recipient_reference, status, created_by, created_at AS occurred_at, consumed_at, revoked_at
			FROM secret_deliveries
			UNION ALL
			SELECT 'secret.consumed' AS event_type, id, title, recipient_reference, status, created_by, consumed_at AS occurred_at, consumed_at, revoked_at
			FROM secret_deliveries
			WHERE consumed_at IS NOT NULL
			UNION ALL
			SELECT 'secret.revoked' AS event_type, id, title, recipient_reference, status, created_by, revoked_at AS occurred_at, consumed_at, revoked_at
			FROM secret_deliveries
			WHERE revoked_at IS NOT NULL
			UNION ALL
			SELECT 'secret.expired' AS event_type, id, title, recipient_reference, status, created_by, updated_at AS occurred_at, consumed_at, revoked_at
			FROM secret_deliveries
			WHERE status = 'expired'
		) events
		WHERE occurred_at IS NOT NULL
		ORDER BY occurred_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []ActivityEvent{}
	for rows.Next() {
		var event ActivityEvent
		if err := rows.Scan(&event.Type, &event.DeliveryID, &event.Title, &event.RecipientReference, &event.Status,
			&event.ActorID, &event.OccurredAt, &event.ConsumedAt, &event.RevokedAt); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
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
		SELECT TRUE, password_hash IS NOT NULL, expires_at
		FROM secret_deliveries
		WHERE token_hash = $1
		  AND status = 'active'
		  AND expires_at > NOW()
		  AND failed_attempts < max_failed_attempts
	`, tokenHash).Scan(&response.MayAttempt, &response.PasswordRequired, &response.ExpiresAt)
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

func normalizeListOptions(opts ListOptions) ListOptions {
	if opts.Page <= 0 {
		opts.Page = 1
	}
	switch opts.PageSize {
	case 10, 25, 50, 100:
	default:
		opts.PageSize = 25
	}
	switch opts.Status {
	case StatusActive, StatusConsuming, StatusConsumed, StatusExpired, StatusRevoked:
	default:
		opts.Status = ""
	}
	if opts.Sort != "expires_at" {
		opts.Sort = "created_at"
	}
	if opts.Order != "asc" {
		opts.Order = "desc"
	}
	opts.Search = strings.TrimSpace(opts.Search)
	return opts
}

func listWhere(opts ListOptions) (string, []any) {
	clauses := []string{"1=1"}
	args := []any{}
	add := func(clause string, value any) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}
	if opts.Status != "" {
		add("status = $%d", opts.Status)
	}
	if opts.Search != "" {
		args = append(args, opts.Search)
		index := len(args)
		clauses = append(clauses, fmt.Sprintf("(title ILIKE '%%' || $%d || '%%' OR recipient_reference ILIKE '%%' || $%d || '%%')", index, index))
	}
	if opts.CreatedFrom != nil {
		add("created_at >= $%d", *opts.CreatedFrom)
	}
	if opts.CreatedTo != nil {
		add("created_at <= $%d", *opts.CreatedTo)
	}
	if opts.ExpiresFrom != nil {
		add("expires_at >= $%d", *opts.ExpiresFrom)
	}
	if opts.ExpiresTo != nil {
		add("expires_at <= $%d", *opts.ExpiresTo)
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}
