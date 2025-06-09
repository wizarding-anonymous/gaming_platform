// File: backend/services/auth-service/internal/domain/entity/role_permission_entity.go
package entity

import (
	"time"
)

// RolePermission represents the link between a role and a permission,
// mapping to the "role_permissions" join table.
type RolePermission struct {
	RoleID       string    `db:"role_id"`
	PermissionID string    `db:"permission_id"`
	CreatedAt    time.Time `db:"created_at"`
}
