// File: backend/services/auth-service/internal/domain/models/refresh_token.go
package models

import (
	"time"

	"github.com/google/uuid"
)

// RefreshToken represents the refresh_token entity in the database,
// aligned with auth_data_model.md and schema after migration 000008.
type RefreshToken struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	SessionID     uuid.UUID  `json:"session_id" db:"session_id"`
	TokenHash     string     `json:"-" db:"token_hash"` // Not usually sent out via APIs
	ExpiresAt     time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"` // Handled by DB default
	RevokedAt     *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	RevokedReason *string    `json:"revoked_reason,omitempty" db:"revoked_reason"`
}
