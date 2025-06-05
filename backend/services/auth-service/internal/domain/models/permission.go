// File: backend/services/auth-service/internal/domain/models/permission.go
package models

import (
	"time"
	// "github.com/google/uuid" // No longer using UUID for Permission ID
)

// Permission represents the permission entity in the database.
// ID is VARCHAR(100) as per auth_data_model.md.
type Permission struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`               // Human-readable name or unique key
	Description string    `json:"description" db:"description"`
	Resource    *string   `json:"resource,omitempty" db:"resource"` // Optional: resource this permission applies to
	Action      *string   `json:"action,omitempty" db:"action"`     // Optional: action this permission allows
	CreatedAt   time.Time `json:"created_at" db:"created_at"`     // Handled by DB default
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`     // Handled by DB trigger
}

// CreatePermissionRequest represents data for creating a new permission.
type CreatePermissionRequest struct {
	ID          string  `json:"id" validate:"required,max=100"` // Permission ID is string
	Name        string  `json:"name" validate:"required,min=3,max=255"`
	Description string  `json:"description" validate:"max=255"`
	Resource    *string `json:"resource,omitempty" validate:"omitempty,max=100"`
	Action      *string `json:"action,omitempty" validate:"omitempty,max=50"`
}

// UpdatePermissionRequest represents data for updating a permission.
type UpdatePermissionRequest struct {
	Name        *string `json:"name,omitempty" validate:"omitempty,min=3,max=255"`
	Description *string `json:"description,omitempty" validate:"max=255"`
	Resource    *string `json:"resource,omitempty" validate:"omitempty,max=100"`
	Action      *string `json:"action,omitempty" validate:"omitempty,max=50"`
}

// PermissionResponse structures the permission data returned by API endpoints.
type PermissionResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Resource    *string   `json:"resource,omitempty"`
	Action      *string   `json:"action,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ToResponse converts a Permission model to an API PermissionResponse.
func (p *Permission) ToResponse() PermissionResponse {
	return PermissionResponse{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		Resource:    p.Resource,
		Action:      p.Action,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
}
