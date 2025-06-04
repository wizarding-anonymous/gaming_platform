package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	"github.com/your-org/auth-service/internal/domain/models"
	"github.com/your-org/auth-service/internal/domain/repository/interfaces" // Corrected path
)

// SessionRepositoryPostgres implements interfaces.SessionRepository for PostgreSQL.
type SessionRepositoryPostgres struct {
	pool *pgxpool.Pool
	// logger *zap.Logger; // Consider adding logger if needed, passed via constructor
}

// NewSessionRepositoryPostgres creates a new instance of SessionRepositoryPostgres.
func NewSessionRepositoryPostgres(pool *pgxpool.Pool /*, logger *zap.Logger*/) *SessionRepositoryPostgres {
	return &SessionRepositoryPostgres{
		pool: pool,
		// logger: logger,
	}
}

// Create persists a new session to the database.
func (r *SessionRepositoryPostgres) Create(ctx context.Context, session *models.Session) error {
	query := `
		INSERT INTO sessions (id, user_id, ip_address, user_agent, device_info, expires_at, last_activity_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	// created_at and updated_at are handled by DB defaults/triggers.
	if session.CreatedAt.IsZero() { // Should be set by service or DB default will take over if not in query
		session.CreatedAt = time.Now()
	}
	if session.LastActivityAt.IsZero() {
		session.LastActivityAt = session.CreatedAt
	}

	_, err := r.pool.Exec(ctx, query,
		session.ID,
		session.UserID,
		session.IPAddress,
		session.UserAgent,
		session.DeviceInfo,
		session.ExpiresAt,
		session.LastActivityAt,
	)
	if err != nil {
		// Log error: r.logger.Error("Failed to create session", zap.Error(err), zap.String("session_id", session.ID.String()))
		return fmt.Errorf("failed to create session: %w", err)
	}
	return nil
}

// GetByID retrieves a session by its unique ID.
func (r *SessionRepositoryPostgres) GetByID(ctx context.Context, id uuid.UUID) (*models.Session, error) {
	query := `
		SELECT id, user_id, ip_address, user_agent, device_info, expires_at, created_at, last_activity_at, updated_at
		FROM sessions
		WHERE id = $1
	`
	s := &models.Session{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&s.ID,
		&s.UserID,
		&s.IPAddress,
		&s.UserAgent,
		&s.DeviceInfo,
		&s.ExpiresAt,
		&s.CreatedAt,
		&s.LastActivityAt,
		&s.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrSessionNotFound
		}
		// Log error
		return nil, fmt.Errorf("failed to get session by ID: %w", err)
	}
	return s, nil
}

// GetUserSessions retrieves sessions for a specific user.
func (r *SessionRepositoryPostgres) GetUserSessions(ctx context.Context, userID uuid.UUID, params models.ListSessionsParams) ([]*models.Session, int, error) {
	var sessions []*models.Session
	var totalCount int

	baseQuery := `
		SELECT id, user_id, ip_address, user_agent, device_info, expires_at, created_at, last_activity_at, updated_at
		FROM sessions
	`
	countQueryBase := `SELECT COUNT(*) FROM sessions`

	conditions := []string{"user_id = $1"}
	args := []interface{}{userID}
	argCount := 2 // Start after userID

	if params.ActiveOnly {
		conditions = append(conditions, fmt.Sprintf("expires_at > $%d", argCount))
		args = append(args, time.Now())
		argCount++
	}

	whereClause := " WHERE " + strings.Join(conditions, " AND ")

	countQueryFull := countQueryBase + whereClause
	err := r.pool.QueryRow(ctx, countQueryFull, args...).Scan(&totalCount)
	if err != nil {
		// Log error
		return nil, 0, fmt.Errorf("failed to count user sessions: %w", err)
	}

	if totalCount == 0 {
		return sessions, 0, nil
	}

	queryFull := baseQuery + whereClause + " ORDER BY last_activity_at DESC"
	if params.PageSize > 0 {
		queryFull += fmt.Sprintf(" LIMIT $%d", argCount)
		args = append(args, params.PageSize)
		argCount++
		if params.Page > 0 {
			offset := (params.Page - 1) * params.PageSize
			queryFull += fmt.Sprintf(" OFFSET $%d", argCount)
			args = append(args, offset)
			// argCount++ // Not needed as it's the last one
		}
	}

	rows, err := r.pool.Query(ctx, queryFull, args...)
	if err != nil {
		// Log error
		return nil, 0, fmt.Errorf("failed to list user sessions: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		s := &models.Session{}
		errScan := rows.Scan(
			&s.ID,
			&s.UserID,
			&s.IPAddress,
			&s.UserAgent,
			&s.DeviceInfo,
			&s.ExpiresAt,
			&s.CreatedAt,
			&s.LastActivityAt,
			&s.UpdatedAt,
		)
		if errScan != nil {
			// Log error
			return nil, 0, fmt.Errorf("failed to scan session row: %w", errScan)
		}
		sessions = append(sessions, s)
	}

	if err = rows.Err(); err != nil {
		// Log error
		return nil, 0, fmt.Errorf("error iterating session rows: %w", err)
	}
	return sessions, totalCount, nil
}

// Update modifies an existing session's details.
func (r *SessionRepositoryPostgres) Update(ctx context.Context, session *models.Session) error {
	query := `
		UPDATE sessions
		SET ip_address = $1, user_agent = $2, device_info = $3, last_activity_at = $4, expires_at = $5
		WHERE id = $6
	`
	// updated_at is handled by trigger.
	// last_activity_at is explicitly updated.
	result, err := r.pool.Exec(ctx, query,
		session.IPAddress,
		session.UserAgent,
		session.DeviceInfo,
		session.LastActivityAt, // Ensure this is updated correctly by caller or a specific method
		session.ExpiresAt,      // ExpiresAt can also be updated (e.g. sliding session)
		session.ID,
	)
	if err != nil {
		// Log error
		return fmt.Errorf("failed to update session: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrSessionNotFound
	}
	return nil
}

// Delete removes a session by its ID.
func (r *SessionRepositoryPostgres) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM sessions WHERE id = $1`
	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		// Log error
		return fmt.Errorf("failed to delete session: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrSessionNotFound
	}
	return nil
}

// DeleteAllUserSessions removes all sessions for a user, optionally excluding one.
func (r *SessionRepositoryPostgres) DeleteAllUserSessions(ctx context.Context, userID uuid.UUID, exceptSessionID *uuid.UUID) (int64, error) {
	query := "DELETE FROM sessions WHERE user_id = $1"
	args := []interface{}{userID}
	argCount := 2

	if exceptSessionID != nil {
		query += fmt.Sprintf(" AND id != $%d", argCount)
		args = append(args, *exceptSessionID)
	}

	result, err := r.pool.Exec(ctx, query, args...)
	if err != nil {
		// Log error
		return 0, fmt.Errorf("failed to delete user sessions: %w", err)
	}
	return result.RowsAffected(), nil
}

// DeleteExpiredSessions removes sessions where expires_at is in the past.
func (r *SessionRepositoryPostgres) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	query := `DELETE FROM sessions WHERE expires_at < NOW()`
	result, err := r.pool.Exec(ctx, query)
	if err != nil {
		// Log error
		return 0, fmt.Errorf("failed to delete expired sessions: %w", err)
	}
	return result.RowsAffected(), nil
}

// --- Cache Methods Implementation (Placeholder/Not Implemented for PostgreSQL) ---
// These methods are part of the interface but would typically be implemented
// by a Redis-specific repository or a composite repository.

func (r *SessionRepositoryPostgres) StoreSessionInCache(ctx context.Context, sessionID uuid.UUID, userID uuid.UUID, ttl time.Duration) error {
	// This is a PostgreSQL repository, caching logic would be elsewhere.
	// r.logger.Warn("StoreSessionInCache called on PostgreSQL repository; this should be handled by a cache repository.")
	return fmt.Errorf("StoreSessionInCache not implemented for PostgreSQL repository")
}

func (r *SessionRepositoryPostgres) GetUserIDFromCache(ctx context.Context, sessionID uuid.UUID) (uuid.UUID, error) {
	// r.logger.Warn("GetUserIDFromCache called on PostgreSQL repository; this should be handled by a cache repository.")
	return uuid.Nil, fmt.Errorf("GetUserIDFromCache not implemented for PostgreSQL repository")
}

func (r *SessionRepositoryPostgres) RemoveSessionFromCache(ctx context.Context, sessionID uuid.UUID) error {
	// r.logger.Warn("RemoveSessionFromCache called on PostgreSQL repository; this should be handled by a cache repository.")
	return fmt.Errorf("RemoveSessionFromCache not implemented for PostgreSQL repository")
}

var _ interfaces.SessionRepository = (*SessionRepositoryPostgres)(nil)
