// File: backend/services/auth-service/internal/domain/models/role.go
package models

import (
	"time"
	// "github.com/google/uuid" // No longer using UUID for Role ID
)

// Role represents the role entity in the database.
// ID is VARCHAR(50) as per auth_data_model.md.
type Role struct {
	ID          string       `json:"id" db:"id"`
	Name        string       `json:"name" db:"name"`
	Description string       `json:"description" db:"description"`
	CreatedAt   time.Time    `json:"created_at" db:"created_at"` // Handled by DB default
	UpdatedAt   time.Time    `json:"updated_at" db:"updated_at"` // Handled by DB trigger
	Permissions []Permission `json:"permissions,omitempty" db:"-"` // Loaded separately
}

// RoleType defines some common predefined role names.
// These are examples; actual role IDs/names will be strings from the DB.
type RoleType string

const (
	RoleGuest       RoleType = "guest"
	RoleUser        RoleType = "user"
	RolePremiumUser RoleType = "premium_user"
	RoleDeveloper   RoleType = "developer"
	RolePublisher   RoleType = "publisher"
	RoleModerator   RoleType = "moderator"
	RoleAdmin       RoleType = "admin"
	RoleSystemAdmin RoleType = "system_admin"
)

// CreateRoleRequest represents the data needed to create a new role.
type CreateRoleRequest struct {
	ID          string   `json:"id" validate:"required,max=50"` // Role ID is string
	Name        string   `json:"name" validate:"required,min=3,max=255"`
	Description string   `json:"description" validate:"max=255"`
	Permissions []string `json:"permissions,omitempty"` // Permission IDs (strings)
}

// UpdateRoleRequest represents data for updating a role.
type UpdateRoleRequest struct {
	Name        *string  `json:"name,omitempty" validate:"omitempty,min=3,max=255"`
	Description *string  `json:"description,omitempty" validate:"max=255"`
	Permissions []string `json:"permissions,omitempty"` // Permission IDs (strings) for full replacement
}

// RoleResponse structures the role data returned by API endpoints.
type RoleResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions,omitempty"` // Permission names or IDs
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ToResponse converts a Role model to an API RoleResponse.
func (r *Role) ToResponse() RoleResponse {
	permissionNames := make([]string, len(r.Permissions))
	for i, p := range r.Permissions {
		permissionNames[i] = p.Name // Assuming Permission struct has a Name field
	}
	return RoleResponse{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Permissions: permissionNames,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}
