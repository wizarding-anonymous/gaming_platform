// File: backend/services/auth-service/internal/infrastructure/database/session_postgres_repository.go
package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gameplatform/auth-service/internal/domain/entity"
	"github.com/gameplatform/auth-service/internal/domain/repository"
)

type pgxSessionRepository struct {
	db *pgxpool.Pool
}

// NewPgxSessionRepository creates a new instance of pgxSessionRepository.
func NewPgxSessionRepository(db *pgxpool.Pool) repository.SessionRepository {
	return &pgxSessionRepository{db: db}
}

func (r *pgxSessionRepository) Create(ctx context.Context, session *entity.Session) error {
	query := `
		INSERT INTO sessions (id, user_id, ip_address, user_agent, device_info, expires_at, created_at, last_activity_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := r.db.Exec(ctx, query,
		session.ID, session.UserID, session.IPAddress, session.UserAgent, session.DeviceInfo,
		session.ExpiresAt, session.CreatedAt, session.LastActivityAt,
	)
	if err != nil {
		// Not expecting unique constraint errors here other than on ID, which should be pre-generated.
		return fmt.Errorf("failed to create session: %w", err)
	}
	return nil
}

func (r *pgxSessionRepository) FindByID(ctx context.Context, id string) (*entity.Session, error) {
	query := `
		SELECT id, user_id, ip_address, user_agent, device_info, expires_at, created_at, last_activity_at 
		FROM sessions 
		WHERE id = $1`
	session := &entity.Session{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&session.ID, &session.UserID, &session.IPAddress, &session.UserAgent, &session.DeviceInfo,
		&session.ExpiresAt, &session.CreatedAt, &session.LastActivityAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("session not found") // Placeholder for entity.ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to find session by ID: %w", err)
	}
	return session, nil
}

func (r *pgxSessionRepository) FindByUserID(ctx context.Context, userID string) ([]*entity.Session, error) {
	query := `
		SELECT id, user_id, ip_address, user_agent, device_info, expires_at, created_at, last_activity_at 
		FROM sessions 
		WHERE user_id = $1 
		ORDER BY last_activity_at DESC` // Or created_at DESC

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to find sessions by user ID: %w", err)
	}
	defer rows.Close()

	var sessions []*entity.Session
	for rows.Next() {
		session := &entity.Session{}
		if err := rows.Scan(
			&session.ID, &session.UserID, &session.IPAddress, &session.UserAgent, &session.DeviceInfo,
			&session.ExpiresAt, &session.CreatedAt, &session.LastActivityAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan session during find by user ID: %w", err)
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error after iterating sessions for user: %w", err)
	}
	return sessions, nil
}

func (r *pgxSessionRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM sessions WHERE id = $1`
	commandTag, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return errors.New("session not found") // Placeholder for entity.ErrSessionNotFound
	}
	return nil
}

func (r *pgxSessionRepository) DeleteByUserID(ctx context.Context, userID string) error {
	// This should also ideally be coupled with deleting associated refresh tokens.
	// That logic might be in a service layer transaction.
	query := `DELETE FROM sessions WHERE user_id = $1`
	_, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete sessions by user ID: %w", err)
	}
	// Not returning error if no rows affected, as the goal is for them to be gone.
	return nil
}

func (r *pgxSessionRepository) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	query := `DELETE FROM sessions WHERE expires_at < $1`
	commandTag, err := r.db.Exec(ctx, query, time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired sessions: %w", err)
	}
	return commandTag.RowsAffected(), nil
}


func (r *pgxSessionRepository) UpdateLastActivityAt(ctx context.Context, id string, lastActivityAt time.Time) error {
	// Note: The 'sessions' table in migration 000006 does not have an 'updated_at' column or trigger.
	// If it did, the trigger would handle it. This method updates only 'last_activity_at'.
	query := `UPDATE sessions SET last_activity_at = $2 WHERE id = $1`
	commandTag, err := r.db.Exec(ctx, query, id, lastActivityAt)
	if err != nil {
		return fmt.Errorf("failed to update session last_activity_at: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return errors.New("session not found") // Placeholder for entity.ErrSessionNotFound
	}
	return nil
}

var _ repository.SessionRepository = (*pgxSessionRepository)(nil)
