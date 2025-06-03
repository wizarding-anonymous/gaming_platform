package models

import (
	"time"

	"github.com/google/uuid"
)

// Role представляет модель роли в системе
type Role struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	Name        string     `json:"name" db:"name"`
	Description string     `json:"description" db:"description"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
	Permissions []Permission `json:"permissions,omitempty" db:"-"`
}

// RoleType определяет предопределенные роли в системе
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

// CreateRoleRequest представляет запрос на создание новой роли
type CreateRoleRequest struct {
	Name        string   `json:"name" validate:"required,min=3,max=50"`
	Description string   `json:"description" validate:"required,max=255"`
	Permissions []string `json:"permissions" validate:"required,min=1"`
}

// UpdateRoleRequest представляет запрос на обновление роли
type UpdateRoleRequest struct {
	Description string   `json:"description" validate:"omitempty,max=255"`
	Permissions []string `json:"permissions" validate:"omitempty"`
}

// AssignRoleRequest представляет запрос на назначение роли пользователю
type AssignRoleRequest struct {
	RoleID string `json:"role_id" validate:"required,uuid"`
}

// RoleResponse представляет ответ с информацией о роли
type RoleResponse struct {
	ID          uuid.UUID   `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Permissions []string    `json:"permissions,omitempty"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// RoleListResponse представляет ответ со списком ролей
type RoleListResponse struct {
	Roles      []RoleResponse `json:"roles"`
	TotalCount int64          `json:"total_count"`
}

// NewRoleFromRequest создает новую модель роли из запроса
func NewRoleFromRequest(req CreateRoleRequest) Role {
	now := time.Now()
	return Role{
		ID:          uuid.New(),
		Name:        req.Name,
		Description: req.Description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// ToResponse преобразует модель роли в ответ API
func (r Role) ToResponse() RoleResponse {
	permissions := make([]string, 0, len(r.Permissions))
	for _, perm := range r.Permissions {
		permissions = append(permissions, perm.Name)
	}

	return RoleResponse{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Permissions: permissions,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}
