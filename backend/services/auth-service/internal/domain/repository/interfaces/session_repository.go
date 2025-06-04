package interfaces

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
)

// SessionRepository defines the interface for interacting with session data.
type SessionRepository interface {
	// Create persists a new session to the database.
	Create(ctx context.Context, session *models.Session) error

	// GetByID retrieves a session by its unique ID.
	// Returns domainErrors.ErrNotFound if no session is found.
	GetByID(ctx context.Context, id uuid.UUID) (*models.Session, error)

	// GetUserSessions retrieves sessions for a specific user.
	// Allows filtering for active sessions and pagination.
	GetUserSessions(ctx context.Context, userID uuid.UUID, params models.ListSessionsParams) ([]*models.Session, int, error)

	// Update modifies an existing session's details in the database.
	// Primarily for attributes like IPAddress, UserAgent, DeviceInfo, or LastActivityAt if not handled by trigger.
	Update(ctx context.Context, session *models.Session) error

	// Delete removes a session by its ID. This is the primary way to "revoke" a session.
	Delete(ctx context.Context, id uuid.UUID) error

	// DeleteAllUserSessions removes all sessions for a given user, optionally excluding one session.
	DeleteAllUserSessions(ctx context.Context, userID uuid.UUID, exceptSessionID *uuid.UUID) (int64, error)
	
	// DeleteExpiredSessions removes all sessions where expires_at is in the past.
	// Returns the number of sessions deleted.
	DeleteExpiredSessions(ctx context.Context) (int64, error)
	
	// --- Cache Methods (can be implemented by a decorator or composite repository) ---

	// StoreSessionInCache saves essential session data (e.g., UserID) to a cache.
	// The actual data stored might be minimal, just enough for quick validation or lookup.
	StoreSessionInCache(ctx context.Context, sessionID uuid.UUID, userID uuid.UUID, ttl time.Duration) error
	
	// GetUserIDFromCache retrieves the UserID associated with a sessionID from the cache.
	// Returns domainErrors.ErrNotFound if not found in cache or expired.
	GetUserIDFromCache(ctx context.Context, sessionID uuid.UUID) (uuid.UUID, error)
	
	// RemoveSessionFromCache explicitly removes a session from the cache.
	RemoveSessionFromCache(ctx context.Context, sessionID uuid.UUID) error
}
