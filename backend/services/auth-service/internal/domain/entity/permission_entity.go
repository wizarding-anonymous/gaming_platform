package entity

import (
	"time"
)

// Permission represents the structure of a permission in the system,
// mapping to the "permissions" table in the database.
type Permission struct {
	ID          string     `db:"id"`
	Name        string     `db:"name"`
	Description *string    `db:"description"` // Nullable
	Resource    *string    `db:"resource"`    // Nullable
	Action      *string    `db:"action"`      // Nullable
	CreatedAt   time.Time  `db:"created_at"`
	UpdatedAt   *time.Time `db:"updated_at"`  // Nullable
}
