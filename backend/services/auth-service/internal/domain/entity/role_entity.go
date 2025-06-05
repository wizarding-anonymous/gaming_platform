// File: backend/services/auth-service/internal/domain/entity/role_entity.go
package entity

import (
	"time"
)

// Role represents the structure of a user role in the system,
// mapping to the "roles" table in the database.
type Role struct {
	ID          string     `db:"id"`
	Name        string     `db:"name"`
	Description *string    `db:"description"` // Nullable
	CreatedAt   time.Time  `db:"created_at"`
	UpdatedAt   *time.Time `db:"updated_at"`  // Nullable
}
