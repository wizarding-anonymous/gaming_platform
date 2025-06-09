// File: backend/services/auth-service/internal/domain/repository/interfaces/token_repository.go
// Package interfaces defines the interfaces for repository implementations.
// (Assuming this package comment is already present from user_repository.go or another file in this package)
package interfaces

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
)

// RefreshTokenRepository defines the interface for interacting with refresh token data.
// While named TokenRepository in the file, its usage in the auth service primarily pertains to refresh tokens.
// It handles storage, retrieval, and revocation of these tokens.
// The actual token value is expected to be hashed before being stored (`TokenHash` field in `models.RefreshToken`).
type RefreshTokenRepository interface { // Renamed from TokenRepository for clarity in this context
	// Create persists a new refresh token to the database.
	// The `models.RefreshToken` should have `SessionID`, `TokenHash`, and `ExpiresAt` populated.
	Create(ctx context.Context, token *models.RefreshToken) error // Changed to pointer and error return

	// FindByID retrieves a refresh token by its unique ID.
	// Returns domainErrors.ErrNotFound if no token is found.
	FindByID(ctx context.Context, id uuid.UUID) (*models.RefreshToken, error) // Renamed, changed to pointer
	
	// FindByTokenHash retrieves a refresh token by its hashed value.
	// This is used to validate an incoming opaque refresh token.
	// IMPORTANT: This method should only return non-revoked and non-expired tokens.
	// Returns domainErrors.ErrNotFound if no matching, valid token is found.
	FindByTokenHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error) // Renamed
	
	// GetByUserAndType was likely for a more generic token system. For refresh tokens, FindByUserID might be more appropriate.
	// FindByUserID retrieves all valid (non-revoked, non-expired) refresh tokens for a given user.
	// This might involve joining with the sessions table.
	// GetByUserAndType(ctx context.Context, userID uuid.UUID, tokenType string) ([]*models.RefreshToken, error) // Assuming RefreshToken model
	
	// Update is generally not used for refresh tokens as they are typically immutable once created.
	// Revocation or re-issuance is preferred. This method might be for other token types.
	// Update(ctx context.Context, token *models.RefreshToken) error
	
	// Delete removes a refresh token by its ID. This is a hard delete.
	// Prefer Revoke for marking tokens as invalid but keeping a record.
	Delete(ctx context.Context, id uuid.UUID) error
	
	// Revoke marks a specific refresh token as revoked by setting its `RevokedAt` timestamp.
	// Returns domainErrors.ErrNotFound if the token to revoke is not found.
	Revoke(ctx context.Context, id uuid.UUID) error
	
	// RevokeAllByUserID marks all refresh tokens associated with a given user (via sessions) as revoked.
	// An optional `exceptTokenID` can be provided to exclude a specific token from revocation (e.g., the current one during a "logout all others" operation).
	// Returns the number of tokens revoked.
	RevokeAllByUserID(ctx context.Context, userID uuid.UUID) (int64, error) // Simplified, exceptTokenID logic might be service layer
	
	// DeleteExpired removes all refresh tokens (and potentially their sessions if cascaded or handled by service)
	// where `expires_at` is in the past. This is a cleanup task.
	// Returns the number of tokens deleted.
	DeleteExpired(ctx context.Context) (int64, error) // Renamed
	
	// IsTokenRevoked checks if a token (by its ID or hash) is marked as revoked.
	// This might be redundant if FindByTokenHash already filters out revoked tokens.
	// IsTokenRevoked(ctx context.Context, tokenID uuid.UUID) (bool, error)
	
	// Caching methods are optional and might be implemented by a decorator.
	// StoreTokenInCache(ctx context.Context, tokenHash string, sessionID uuid.UUID, expiresIn time.Duration) error
	// GetSessionIDFromCache(ctx context.Context, tokenHash string) (uuid.UUID, error)
	// RemoveTokenFromCache(ctx context.Context, tokenHash string) error
}
