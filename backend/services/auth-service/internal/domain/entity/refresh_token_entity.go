package entity

import (
	"time"
)

// RefreshToken represents a refresh token associated with a user session,
// mapping to the "refresh_tokens" table.
type RefreshToken struct {
	ID            string     `db:"id"`
	SessionID     string     `db:"session_id"`
	TokenHash     string     `db:"token_hash"`
	ExpiresAt     time.Time  `db:"expires_at"`
	CreatedAt     time.Time  `db:"created_at"`
	RevokedAt     *time.Time `db:"revoked_at"`     // Nullable
	RevokedReason *string    `db:"revoked_reason"` // Nullable
}
