package entity

import (
	"encoding/json"
	"time"
)

// Session represents a user session in the system,
// mapping to the "sessions" table.
type Session struct {
	ID             string          `db:"id"`
	UserID         string          `db:"user_id"`
	IPAddress      *string         `db:"ip_address"`       // Nullable
	UserAgent      *string         `db:"user_agent"`       // Nullable
	DeviceInfo     json.RawMessage `db:"device_info"`      // Nullable JSONB
	ExpiresAt      time.Time       `db:"expires_at"`
	CreatedAt      time.Time       `db:"created_at"`
	LastActivityAt *time.Time      `db:"last_activity_at"` // Nullable
}
