// File: internal/repository/postgres/token_repository.go

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"go.uber.org/zap"
)

// TokenRepository реализует интерфейс для работы с токенами в PostgreSQL
type TokenRepository struct {
	db     *sqlx.DB
	logger *zap.Logger
}

// NewTokenRepository создает новый экземпляр TokenRepository
func NewTokenRepository(db *sqlx.DB, logger *zap.Logger) *TokenRepository {
	return &TokenRepository{
		db:     db,
		logger: logger,
	}
}

// GetByID получает токен по ID
func (r *TokenRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Token, error) {
	query := `
		SELECT id, user_id, token_type, token_value, expires_at, created_at, revoked, revoked_at
		FROM tokens
		WHERE id = $1
	`

	var token models.Token
	err := r.db.GetContext(ctx, &token, query, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, models.ErrTokenNotFound
		}
		r.logger.Error("Failed to get token by ID", zap.Error(err), zap.String("token_id", id.String()))
		return nil, err
	}

	return &token, nil
}

// GetByValue получает токен по значению
func (r *TokenRepository) GetByValue(ctx context.Context, value string) (*models.Token, error) {
	query := `
		SELECT id, user_id, token_type, token_value, expires_at, created_at, revoked, revoked_at
		FROM tokens
		WHERE token_value = $1
	`

	var token models.Token
	err := r.db.GetContext(ctx, &token, query, value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, models.ErrTokenNotFound
		}
		r.logger.Error("Failed to get token by value", zap.Error(err))
		return nil, err
	}

	return &token, nil
}

// GetByUserID получает токены пользователя
func (r *TokenRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*models.Token, error) {
	query := `
		SELECT id, user_id, token_type, token_value, expires_at, created_at, revoked, revoked_at
		FROM tokens
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	var tokens []*models.Token
	err := r.db.SelectContext(ctx, &tokens, query, userID)
	if err != nil {
		r.logger.Error("Failed to get tokens by user ID", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, err
	}

	return tokens, nil
}

// GetActiveByUserID получает активные токены пользователя
func (r *TokenRepository) GetActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*models.Token, error) {
	query := `
		SELECT id, user_id, token_type, token_value, expires_at, created_at, revoked, revoked_at
		FROM tokens
		WHERE user_id = $1 AND revoked = false AND expires_at > $2
		ORDER BY created_at DESC
	`

	var tokens []*models.Token
	err := r.db.SelectContext(ctx, &tokens, query, userID, time.Now())
	if err != nil {
		r.logger.Error("Failed to get active tokens by user ID", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, err
	}

	return tokens, nil
}

// Create создает новый токен
func (r *TokenRepository) Create(ctx context.Context, token *models.Token) error {
	query := `
		INSERT INTO tokens (id, user_id, token_type, token_value, expires_at, created_at, revoked, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		token.ID,
		token.UserID,
		token.TokenType,
		token.TokenValue,
		token.ExpiresAt,
		token.CreatedAt,
		token.Revoked,
		token.RevokedAt,
	)
	if err != nil {
		r.logger.Error("Failed to create token", zap.Error(err), zap.String("token_id", token.ID.String()))
		return err
	}

	return nil
}

// Update обновляет токен
func (r *TokenRepository) Update(ctx context.Context, token *models.Token) error {
	query := `
		UPDATE tokens
		SET token_value = $1, expires_at = $2, revoked = $3, revoked_at = $4
		WHERE id = $5
	`

	result, err := r.db.ExecContext(
		ctx,
		query,
		token.TokenValue,
		token.ExpiresAt,
		token.Revoked,
		token.RevokedAt,
		token.ID,
	)
	if err != nil {
		r.logger.Error("Failed to update token", zap.Error(err), zap.String("token_id", token.ID.String()))
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.Error("Failed to get rows affected", zap.Error(err))
		return err
	}

	if rowsAffected == 0 {
		return models.ErrTokenNotFound
	}

	return nil
}

// Delete удаляет токен
func (r *TokenRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `
		DELETE FROM tokens
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("Failed to delete token", zap.Error(err), zap.String("token_id", id.String()))
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.Error("Failed to get rows affected", zap.Error(err))
		return err
	}

	if rowsAffected == 0 {
		return models.ErrTokenNotFound
	}

	return nil
}

// RevokeToken отзывает токен
func (r *TokenRepository) RevokeToken(ctx context.Context, tokenValue string) error {
	query := `
		UPDATE tokens
		SET revoked = true, revoked_at = $1
		WHERE token_value = $2 AND revoked = false
	`

	result, err := r.db.ExecContext(ctx, query, time.Now(), tokenValue)
	if err != nil {
		r.logger.Error("Failed to revoke token", zap.Error(err))
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.Error("Failed to get rows affected", zap.Error(err))
		return err
	}

	if rowsAffected == 0 {
		return models.ErrTokenNotFound
	}

	return nil
}

// RevokeAllUserTokens отзывает все токены пользователя
func (r *TokenRepository) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE tokens
		SET revoked = true, revoked_at = $1
		WHERE user_id = $2 AND revoked = false
	`

	_, err := r.db.ExecContext(ctx, query, time.Now(), userID)
	if err != nil {
		r.logger.Error("Failed to revoke all user tokens", zap.Error(err), zap.String("user_id", userID.String()))
		return err
	}

	return nil
}

// DeleteExpired удаляет истекшие токены
func (r *TokenRepository) DeleteExpired(ctx context.Context) (int, error) {
	query := `
		DELETE FROM tokens
		WHERE expires_at < $1
	`

	result, err := r.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		r.logger.Error("Failed to delete expired tokens", zap.Error(err))
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.Error("Failed to get rows affected", zap.Error(err))
		return 0, err
	}

	return int(rowsAffected), nil
}
