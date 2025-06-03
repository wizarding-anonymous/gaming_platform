package models

import (
	"time"

	"github.com/google/uuid"
)

// Permission представляет модель разрешения в системе
type Permission struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// PermissionType определяет предопределенные разрешения в системе
type PermissionType string

const (
	// Разрешения для пользователей
	PermUserRead       PermissionType = "users.read"
	PermUserWrite      PermissionType = "users.write"
	PermUserDelete     PermissionType = "users.delete"
	
	// Разрешения для ролей
	PermRoleRead       PermissionType = "roles.read"
	PermRoleWrite      PermissionType = "roles.write"
	PermRoleDelete     PermissionType = "roles.delete"
	
	// Разрешения для игр
	PermGameRead       PermissionType = "games.read"
	PermGameWrite      PermissionType = "games.write"
	PermGameDelete     PermissionType = "games.delete"
	PermGamePublish    PermissionType = "games.publish"
	
	// Разрешения для контента
	PermContentRead    PermissionType = "content.read"
	PermContentWrite   PermissionType = "content.write"
	PermContentDelete  PermissionType = "content.delete"
	PermContentModerate PermissionType = "content.moderate"
	
	// Разрешения для платежей
	PermPaymentRead    PermissionType = "payments.read"
	PermPaymentWrite   PermissionType = "payments.write"
	PermPaymentRefund  PermissionType = "payments.refund"
	
	// Разрешения для администрирования
	PermAdminAccess    PermissionType = "admin.access"
	PermSystemAccess   PermissionType = "system.access"
)

// CreatePermissionRequest представляет запрос на создание нового разрешения
type CreatePermissionRequest struct {
	Name        string `json:"name" validate:"required,min=3,max=50"`
	Description string `json:"description" validate:"required,max=255"`
}

// UpdatePermissionRequest представляет запрос на обновление разрешения
type UpdatePermissionRequest struct {
	Description string `json:"description" validate:"required,max=255"`
}

// PermissionResponse представляет ответ с информацией о разрешении
type PermissionResponse struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PermissionListResponse представляет ответ со списком разрешений
type PermissionListResponse struct {
	Permissions []PermissionResponse `json:"permissions"`
	TotalCount  int64               `json:"total_count"`
}

// NewPermissionFromRequest создает новую модель разрешения из запроса
func NewPermissionFromRequest(req CreatePermissionRequest) Permission {
	now := time.Now()
	return Permission{
		ID:          uuid.New(),
		Name:        req.Name,
		Description: req.Description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// ToResponse преобразует модель разрешения в ответ API
func (p Permission) ToResponse() PermissionResponse {
	return PermissionResponse{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
}

// CheckPermissionRequest представляет запрос на проверку наличия разрешения
type CheckPermissionRequest struct {
	Permission string `json:"permission" validate:"required"`
}

// CheckPermissionResponse представляет ответ на проверку наличия разрешения
type CheckPermissionResponse struct {
	HasPermission bool `json:"has_permission"`
}
