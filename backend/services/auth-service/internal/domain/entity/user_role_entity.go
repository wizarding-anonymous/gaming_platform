package entity

import (
	"time"
)

// UserRole represents the link between a user and a role,
// mapping to the "user_roles" join table.
type UserRole struct {
	UserID     string    `db:"user_id"`
	RoleID     string    `db:"role_id"`
	AssignedBy *string   `db:"assigned_by"` // Nullable UUID
	CreatedAt  time.Time `db:"created_at"`
}
