// File: backend/services/auth-service/internal/infrastructure/database/refresh_token_postgres_repository.go
package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/entity"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository"
)

type pgxRefreshTokenRepository struct {
	db *pgxpool.Pool
}

// NewPgxRefreshTokenRepository creates a new instance of pgxRefreshTokenRepository.
func NewPgxRefreshTokenRepository(db *pgxpool.Pool) repository.RefreshTokenRepository {
	return &pgxRefreshTokenRepository{db: db}
}

func (r *pgxRefreshTokenRepository) Create(ctx context.Context, token *entity.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, session_id, token_hash, expires_at, created_at, revoked_at, revoked_reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.db.Exec(ctx, query,
		token.ID, token.SessionID, token.TokenHash, token.ExpiresAt,
		token.CreatedAt, token.RevokedAt, token.RevokedReason,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // Unique violation for token_hash or id
			return errors.New("refresh token with given id or hash already exists: " + pgErr.Detail) // Placeholder
		}
		return fmt.Errorf("failed to create refresh token: %w", err)
	}
	return nil
}

func (r *pgxRefreshTokenRepository) FindByID(ctx context.Context, id string) (*entity.RefreshToken, error) {
	query := `
		SELECT id, session_id, token_hash, expires_at, created_at, revoked_at, revoked_reason
		FROM refresh_tokens
		WHERE id = $1`
	token := &entity.RefreshToken{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&token.ID, &token.SessionID, &token.TokenHash, &token.ExpiresAt,
		&token.CreatedAt, &token.RevokedAt, &token.RevokedReason,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("refresh token not found") // Placeholder for entity.ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("failed to find refresh token by ID: %w", err)
	}
	return token, nil
}

func (r *pgxRefreshTokenRepository) FindByTokenHash(ctx context.Context, tokenHash string) (*entity.RefreshToken, error) {
	query := `
		SELECT id, session_id, token_hash, expires_at, created_at, revoked_at, revoked_reason
		FROM refresh_tokens
		WHERE token_hash = $1`
	token := &entity.RefreshToken{}
	err := r.db.QueryRow(ctx, query, tokenHash).Scan(
		&token.ID, &token.SessionID, &token.TokenHash, &token.ExpiresAt,
		&token.CreatedAt, &token.RevokedAt, &token.RevokedReason,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("refresh token not found") // Placeholder for entity.ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("failed to find refresh token by hash: %w", err)
	}
	return token, nil
}

func (r *pgxRefreshTokenRepository) FindBySessionID(ctx context.Context, sessionID string) (*entity.RefreshToken, error) {
	// This typically assumes one active refresh token per session.
	// If multiple are possible, this should return a slice or be more specific.
	query := `
		SELECT id, session_id, token_hash, expires_at, created_at, revoked_at, revoked_reason
		FROM refresh_tokens
		WHERE session_id = $1 AND revoked_at IS NULL
		ORDER BY created_at DESC LIMIT 1` // Get the latest active one
	token := &entity.RefreshToken{}
	err := r.db.QueryRow(ctx, query, sessionID).Scan(
		&token.ID, &token.SessionID, &token.TokenHash, &token.ExpiresAt,
		&token.CreatedAt, &token.RevokedAt, &token.RevokedReason,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("active refresh token for session not found") // Placeholder
		}
		return nil, fmt.Errorf("failed to find refresh token by session ID: %w", err)
	}
	return token, nil
}


func (r *pgxRefreshTokenRepository) Revoke(ctx context.Context, id string, revokedAt time.Time, reason string) error {
	query := `UPDATE refresh_tokens SET revoked_at = $2, revoked_reason = $3 WHERE id = $1 AND revoked_at IS NULL`
	commandTag, err := r.db.Exec(ctx, query, id, revokedAt, reason)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return errors.New("refresh token not found or already revoked") // Placeholder for entity.ErrRefreshTokenNotFound
	}
	return nil
}

func (r *pgxRefreshTokenRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM refresh_tokens WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}
	// Not checking RowsAffected, as goal is for it to be gone.
	return nil
}

func (r *pgxRefreshTokenRepository) DeleteBySessionID(ctx context.Context, sessionID string) error {
	query := `DELETE FROM refresh_tokens WHERE session_id = $1`
	_, err := r.db.Exec(ctx, query, sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete refresh tokens by session ID: %w", err)
	}
	return nil
}

func (r *pgxRefreshTokenRepository) DeleteExpiredAndRevoked(ctx context.Context, olderThanRevoked time.Duration) (int64, error) {
	// Delete tokens that are expired OR (revoked for longer than 'olderThanRevoked' period)
	// The 'olderThanRevoked' helps to keep revoked tokens for a while for audit/detection purposes.
	cutoffRevokedTime := time.Now().Add(-olderThanRevoked)
	query := `
		DELETE FROM refresh_tokens 
		WHERE expires_at < $1 OR (revoked_at IS NOT NULL AND revoked_at < $2)`
	
	commandTag, err := r.db.Exec(ctx, query, time.Now(), cutoffRevokedTime)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired and revoked refresh tokens: %w", err)
	}
	return commandTag.RowsAffected(), nil
}


var _ repository.RefreshTokenRepository = (*pgxRefreshTokenRepository)(nil)
