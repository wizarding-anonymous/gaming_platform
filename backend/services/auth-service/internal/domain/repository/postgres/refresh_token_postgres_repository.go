// File: backend/services/auth-service/internal/domain/repository/postgres/refresh_token_postgres_repository.go
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	"github.com/your-org/auth-service/internal/domain/models"
	"github.com/your-org/auth-service/internal/domain/repository"
)

// RefreshTokenRepositoryPostgres implements repository.RefreshTokenRepository
type RefreshTokenRepositoryPostgres struct {
	pool *pgxpool.Pool
}

// NewRefreshTokenRepositoryPostgres creates a new RefreshTokenRepositoryPostgres.
func NewRefreshTokenRepositoryPostgres(pool *pgxpool.Pool) *RefreshTokenRepositoryPostgres {
	return &RefreshTokenRepositoryPostgres{pool: pool}
}

// Create persists a new refresh token.
func (r *RefreshTokenRepositoryPostgres) Create(ctx context.Context, token *models.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, session_id, token_hash, expires_at, revoked_at, revoked_reason)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	// created_at has a DB default and is not set explicitly here.
	_, err := r.pool.Exec(ctx, query,
		token.ID, token.SessionID, token.TokenHash, token.ExpiresAt, token.RevokedAt, token.RevokedReason,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			// Assuming token_hash should be unique for active tokens,
			// or (session_id, token_hash) for broader uniqueness.
			// The current schema has token_hash UNIQUE.
			return fmt.Errorf("failed to create refresh token due to unique constraint on token_hash: %w", domainErrors.ErrDuplicateValue)
		}
		return fmt.Errorf("failed to create refresh token: %w", err)
	}
	return nil
}

// FindByID retrieves a refresh token by its ID.
func (r *RefreshTokenRepositoryPostgres) FindByID(ctx context.Context, id uuid.UUID) (*models.RefreshToken, error) {
	query := `
		SELECT id, session_id, token_hash, expires_at, created_at, revoked_at, revoked_reason
		FROM refresh_tokens
		WHERE id = $1
	`
	rt := &models.RefreshToken{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&rt.ID, &rt.SessionID, &rt.TokenHash, &rt.ExpiresAt, &rt.CreatedAt, &rt.RevokedAt, &rt.RevokedReason,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound // Consider specific ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("failed to find refresh token by ID: %w", err)
	}
	return rt, nil
}

// FindByTokenHash retrieves an active refresh token by its hashed value.
func (r *RefreshTokenRepositoryPostgres) FindByTokenHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	query := `
		SELECT id, session_id, token_hash, expires_at, created_at, revoked_at, revoked_reason
		FROM refresh_tokens
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()
	`
	rt := &models.RefreshToken{}
	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&rt.ID, &rt.SessionID, &rt.TokenHash, &rt.ExpiresAt, &rt.CreatedAt, &rt.RevokedAt, &rt.RevokedReason,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound // Consider specific ErrRefreshTokenNotFound or ErrInvalidToken
		}
		return nil, fmt.Errorf("failed to find refresh token by hash: %w", err)
	}
	return rt, nil
}

// FindBySessionID retrieves the active refresh token for a given session ID.
func (r *RefreshTokenRepositoryPostgres) FindBySessionID(ctx context.Context, sessionID uuid.UUID) (*models.RefreshToken, error) {
	query := `
		SELECT id, session_id, token_hash, expires_at, created_at, revoked_at, revoked_reason
		FROM refresh_tokens
		WHERE session_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
		ORDER BY created_at DESC
		LIMIT 1
	`
	rt := &models.RefreshToken{}
	err := r.pool.QueryRow(ctx, query, sessionID).Scan(
		&rt.ID, &rt.SessionID, &rt.TokenHash, &rt.ExpiresAt, &rt.CreatedAt, &rt.RevokedAt, &rt.RevokedReason,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to find refresh token by session ID: %w", err)
	}
	return rt, nil
}

// Revoke marks a refresh token as revoked.
func (r *RefreshTokenRepositoryPostgres) Revoke(ctx context.Context, id uuid.UUID, reason *string) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = $1
		WHERE id = $2 AND revoked_at IS NULL
	`
	result, err := r.pool.Exec(ctx, query, reason, id)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrNotFound // Or already revoked
	}
	return nil
}

// Delete removes a refresh token by its ID.
func (r *RefreshTokenRepositoryPostgres) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM refresh_tokens WHERE id = $1`
	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrNotFound
	}
	return nil
}

// DeleteBySessionID removes all refresh tokens for a given session ID.
func (r *RefreshTokenRepositoryPostgres) DeleteBySessionID(ctx context.Context, sessionID uuid.UUID) error {
	query := `DELETE FROM refresh_tokens WHERE session_id = $1`
	_, err := r.pool.Exec(ctx, query, sessionID) // RowsAffected might not be critical here
	if err != nil {
		return fmt.Errorf("failed to delete refresh tokens by session ID: %w", err)
	}
	return nil
}

// DeleteExpiredAndRevoked removes expired tokens and tokens revoked longer than the specified duration.
func (r *RefreshTokenRepositoryPostgres) DeleteExpiredAndRevoked(ctx context.Context, olderThanRevokedPeriod time.Duration) (int64, error) {
	var totalDeleted int64

	// Delete expired tokens
	queryExpired := `DELETE FROM refresh_tokens WHERE expires_at < NOW()`
	expiredResult, err := r.pool.Exec(ctx, queryExpired)
	if err != nil {
		return totalDeleted, fmt.Errorf("failed to delete expired refresh tokens: %w", err)
	}
	totalDeleted += expiredResult.RowsAffected()

	// Delete revoked tokens older than the specified period
	if olderThanRevokedPeriod > 0 {
		queryRevoked := `
			DELETE FROM refresh_tokens
			WHERE revoked_at IS NOT NULL AND revoked_at < (CURRENT_TIMESTAMP - $1::interval)
		`
		// Convert duration to string like "X days" or "X hours" for interval
		// This is a bit simplistic; interval format can be complex.
		// For pgx, sending duration directly might not work, string interval is safer.
		// Example: olderThanRevokedPeriod.Hours()/24 for days
		intervalStr := fmt.Sprintf("%f seconds", olderThanRevokedPeriod.Seconds())

		revokedResult, err := r.pool.Exec(ctx, queryRevoked, intervalStr)
		if err != nil {
			return totalDeleted, fmt.Errorf("failed to delete old revoked refresh tokens: %w", err)
		}
		totalDeleted += revokedResult.RowsAffected()
	} else {
		// If olderThanRevokedPeriod is zero, delete all revoked tokens
		queryAllRevoked := `DELETE FROM refresh_tokens WHERE revoked_at IS NOT NULL`
		revokedResult, err := r.pool.Exec(ctx, queryAllRevoked)
		if err != nil {
			return totalDeleted, fmt.Errorf("failed to delete all revoked refresh tokens: %w", err)
		}
		totalDeleted += revokedResult.RowsAffected()
	}

	return totalDeleted, nil
}

// DeleteByUserID removes all refresh tokens for a specific user.
func (r *RefreshTokenRepositoryPostgres) DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
	query := `DELETE FROM refresh_tokens WHERE user_id = $1`
	result, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to delete refresh tokens by user ID: %w", err)
	}
	return result.RowsAffected(), nil
}

var _ repository.RefreshTokenRepository = (*RefreshTokenRepositoryPostgres)(nil)
