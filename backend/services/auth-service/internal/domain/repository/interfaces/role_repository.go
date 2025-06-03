package interfaces

import (
	"context"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
)

// RoleRepository определяет интерфейс для работы с ролями в хранилище
type RoleRepository interface {
	// Create создает новую роль
	Create(ctx context.Context, role models.Role) (models.Role, error)
	
	// GetByID получает роль по ID
	GetByID(ctx context.Context, id uuid.UUID) (models.Role, error)
	
	// GetByName получает роль по имени
	GetByName(ctx context.Context, name string) (models.Role, error)
	
	// Update обновляет информацию о роли
	Update(ctx context.Context, role models.Role) error
	
	// Delete удаляет роль
	Delete(ctx context.Context, id uuid.UUID) error
	
	// List получает список ролей
	List(ctx context.Context) ([]models.Role, error)
	
	// GetRolePermissions получает разрешения роли
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]models.Permission, error)
	
	// AssignPermission назначает разрешение роли
	AssignPermission(ctx context.Context, roleID, permissionID uuid.UUID) error
	
	// RemovePermission удаляет разрешение у роли
	RemovePermission(ctx context.Context, roleID, permissionID uuid.UUID) error
	
	// HasPermission проверяет, имеет ли роль указанное разрешение
	HasPermission(ctx context.Context, roleID uuid.UUID, permissionName string) (bool, error)
}
