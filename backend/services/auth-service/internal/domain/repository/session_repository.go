// File: backend/services/auth-service/internal/domain/repository/session_repository.go
package repository

import (
	"context"
	"time"

	"github.com/gameplatform/auth-service/internal/domain/entity"
)

// SessionRepository defines the interface for interacting with user session data.
type SessionRepository interface {
	// Create persists a new session to the database.
	Create(ctx context.Context, session *entity.Session) error

	// FindByID retrieves a session by its unique ID.
	// Returns entity.ErrSessionNotFound if no session is found.
	FindByID(ctx context.Context, id string) (*entity.Session, error)

	// FindByUserID retrieves all active sessions for a given user ID.
	// Should typically order by created_at or last_activity_at.
	FindByUserID(ctx context.Context, userID string) ([]*entity.Session, error)

	// Delete removes a session by its ID (e.g., when a refresh token associated with it is revoked).
	Delete(ctx context.Context, id string) error

	// DeleteByUserID removes all sessions for a given user ID (e.g., for "logout all devices").
	// This might also involve revoking associated refresh tokens.
	DeleteByUserID(ctx context.Context, userID string) error
	
	// DeleteExpiredSessions removes sessions that have passed their expires_at time.
	DeleteExpiredSessions(ctx context.Context) (int64, error) // Returns number of sessions deleted

	// UpdateLastActivityAt updates the last_activity_at timestamp for a session.
	UpdateLastActivityAt(ctx context.Context, id string, lastActivityAt time.Time) error
}

// Note: entity.ErrSessionNotFound would be a custom error.
// Define in an appropriate error definitions file.
// Example:
// package entity
// import "errors"
// var ErrSessionNotFound = errors.New("session not found")
