// File: internal/repository/postgres/session_repository.go

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/your-org/auth-service/internal/domain/models"
	"go.uber.org/zap"
)

// SessionRepository реализует интерфейс для работы с сессиями в PostgreSQL
type SessionRepository struct {
	db     *sqlx.DB
	logger *zap.Logger
}

// NewSessionRepository создает новый экземпляр SessionRepository
func NewSessionRepository(db *sqlx.DB, logger *zap.Logger) *SessionRepository {
	return &SessionRepository{
		db:     db,
		logger: logger,
	}
}

// GetByID получает сессию по ID
func (r *SessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Session, error) {
	query := `
		SELECT id, user_id, user_agent, ip_address, created_at, updated_at, expires_at, is_active
		FROM sessions
		WHERE id = $1
	`

	var session models.Session
	err := r.db.GetContext(ctx, &session, query, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, models.ErrSessionNotFound
		}
		r.logger.Error("Failed to get session by ID", zap.Error(err), zap.String("session_id", id.String()))
		return nil, err
	}

	return &session, nil
}

// GetByUserID получает все сессии пользователя
func (r *SessionRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	query := `
		SELECT id, user_id, user_agent, ip_address, created_at, updated_at, expires_at, is_active
		FROM sessions
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	var sessions []*models.Session
	err := r.db.SelectContext(ctx, &sessions, query, userID)
	if err != nil {
		r.logger.Error("Failed to get sessions by user ID", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, err
	}

	return sessions, nil
}

// GetActiveByUserID получает активные сессии пользователя
func (r *SessionRepository) GetActiveByUserID(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	query := `
		SELECT id, user_id, user_agent, ip_address, created_at, updated_at, expires_at, is_active
		FROM sessions
		WHERE user_id = $1 AND is_active = true AND expires_at > $2
		ORDER BY created_at DESC
	`

	var sessions []*models.Session
	err := r.db.SelectContext(ctx, &sessions, query, userID, time.Now())
	if err != nil {
		r.logger.Error("Failed to get active sessions by user ID", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, err
	}

	return sessions, nil
}

// Create создает новую сессию
func (r *SessionRepository) Create(ctx context.Context, session *models.Session) error {
	query := `
		INSERT INTO sessions (id, user_id, user_agent, ip_address, created_at, updated_at, expires_at, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		session.ID,
		session.UserID,
		session.UserAgent,
		session.IPAddress,
		session.CreatedAt,
		session.CreatedAt, // updated_at = created_at при создании
		session.ExpiresAt,
		session.IsActive,
	)
	if err != nil {
		r.logger.Error("Failed to create session", zap.Error(err), zap.String("session_id", session.ID.String()))
		return err
	}

	return nil
}

// Update обновляет сессию
func (r *SessionRepository) Update(ctx context.Context, session *models.Session) error {
	query := `
		UPDATE sessions
		SET user_agent = $1, ip_address = $2, updated_at = $3, expires_at = $4, is_active = $5
		WHERE id = $6
	`

	result, err := r.db.ExecContext(
		ctx,
		query,
		session.UserAgent,
		session.IPAddress,
		time.Now(),
		session.ExpiresAt,
		session.IsActive,
		session.ID,
	)
	if err != nil {
		r.logger.Error("Failed to update session", zap.Error(err), zap.String("session_id", session.ID.String()))
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.Error("Failed to get rows affected", zap.Error(err))
		return err
	}

	if rowsAffected == 0 {
		return models.ErrSessionNotFound
	}

	return nil
}

// Delete удаляет сессию
func (r *SessionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `
		DELETE FROM sessions
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("Failed to delete session", zap.Error(err), zap.String("session_id", id.String()))
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.Error("Failed to get rows affected", zap.Error(err))
		return err
	}

	if rowsAffected == 0 {
		return models.ErrSessionNotFound
	}

	return nil
}

// DeactivateAllByUserID деактивирует все сессии пользователя
func (r *SessionRepository) DeactivateAllByUserID(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE sessions
		SET is_active = false, updated_at = $1
		WHERE user_id = $2 AND is_active = true
	`

	_, err := r.db.ExecContext(ctx, query, time.Now(), userID)
	if err != nil {
		r.logger.Error("Failed to deactivate all user sessions", zap.Error(err), zap.String("user_id", userID.String()))
		return err
	}

	return nil
}

// DeleteExpired удаляет истекшие сессии
func (r *SessionRepository) DeleteExpired(ctx context.Context) (int, error) {
	query := `
		DELETE FROM sessions
		WHERE expires_at < $1
	`

	result, err := r.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		r.logger.Error("Failed to delete expired sessions", zap.Error(err))
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.Error("Failed to get rows affected", zap.Error(err))
		return 0, err
	}

	return int(rowsAffected), nil
}
