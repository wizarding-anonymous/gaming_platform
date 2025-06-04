package entity

import (
	"encoding/json"
	"time"
)

// APIKey represents an API key for programmatic access,
// mapping to the "api_keys" table.
type APIKey struct {
	ID          string          `db:"id"`
	UserID      string          `db:"user_id"`
	Name        string          `db:"name"`
	KeyPrefix   string          `db:"key_prefix"`
	KeyHash     string          `db:"key_hash"`
	Permissions json.RawMessage `db:"permissions"`   // Nullable JSONB, expected to store []string
	ExpiresAt   *time.Time      `db:"expires_at"`    // Nullable
	CreatedAt   time.Time       `db:"created_at"`
	LastUsedAt  *time.Time      `db:"last_used_at"`  // Nullable
	RevokedAt   *time.Time      `db:"revoked_at"`    // Nullable
	UpdatedAt   *time.Time      `db:"updated_at"`    // Nullable
}
