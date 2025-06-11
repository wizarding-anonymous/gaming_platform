// File: backend/services/auth-service/internal/domain/repository/interfaces/session_repository.go
// Package interfaces defines the interfaces for repository implementations.
// (Assuming this package comment is already present from user_repository.go or another file in this package)
package interfaces

import (
	"context"
	"time"

	"github.com/google/uuid"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors" // Added for ErrNotFound
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
)

// SessionRepository defines the interface for managing user sessions in the data store.
// It includes methods for creating, retrieving, updating, and deleting sessions,
// as well as handling session expiration and potentially caching.
type SessionRepository interface {
	// Create persists a new session to the database.
	// It takes a models.Session object, which should have UserID, UserAgent, IPAddress, and ExpiresAt populated.
	Create(ctx context.Context, session *models.Session) error

	// FindByID retrieves a session by its unique ID. (Changed from GetByID for consistency with other repos)
	// Returns domainErrors.ErrNotFound if no session is found.
	FindByID(ctx context.Context, id uuid.UUID) (*models.Session, error)

	// FindByUserID retrieves all sessions for a specific user.
	// It returns every session row for the user without additional filtering.
	FindByUserID(ctx context.Context, userID uuid.UUID) ([]*models.Session, error)

	// UpdateLastActivityAt updates the last activity timestamp for a given session ID.
	// This is important for tracking active sessions and determining inactivity for expiration.
	UpdateLastActivityAt(ctx context.Context, id uuid.UUID, lastActivityAt time.Time) error

	// Delete removes a session by its ID. This is the primary way to "revoke" or invalidate a session.
	// Returns domainErrors.ErrNotFound if the session to delete is not found.
	Delete(ctx context.Context, id uuid.UUID) error

	// DeleteAllByUserID removes all sessions for a given user, optionally excluding one specified sessionID.
	// This is useful for "logout all other devices" functionality or when a user's account is compromised/deleted.
	// Returns the number of sessions deleted and an error if any.
	DeleteAllByUserID(ctx context.Context, userID uuid.UUID, exceptSessionID *uuid.UUID) (int64, error) // Changed from DeleteAllUserSessions

	// DeleteExpired removes all sessions where expires_at is in the past.
	// This is a cleanup task that should be run periodically.
	// Returns the number of sessions deleted and an error if any.
	DeleteExpired(ctx context.Context) (int64, error) // Changed from DeleteExpiredSessions

	// --- Cache Methods (These are optional and might be part of a decorated repository) ---

	// StoreInCache saves essential session data (e.g., UserID) to a cache with a TTL.
	// The actual data stored might be minimal, just enough for quick validation or lookup.
	// This can help reduce database load for frequent session checks.
	StoreInCache(ctx context.Context, sessionID uuid.UUID, userID uuid.UUID, ttl time.Duration) error // Renamed

	// GetUserIDFromCache retrieves the UserID associated with a sessionID from the cache.
	// Returns domainErrors.ErrNotFound if the sessionID is not found in the cache or if it has expired.
	GetUserIDFromCache(ctx context.Context, sessionID uuid.UUID) (uuid.UUID, error)

	// RemoveFromCache explicitly removes a session from the cache, e.g., on logout.
	RemoveFromCache(ctx context.Context, sessionID uuid.UUID) error // Renamed
}
