// File: internal/service/role_service.go

package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
	"github.com/your-org/auth-service/internal/repository/interfaces"
	"github.com/your-org/auth-service/internal/utils/kafka"
	"go.uber.org/zap"
)

// RoleService предоставляет методы для работы с ролями
type RoleService struct {
	roleRepo    interfaces.RoleRepository
	userRepo    interfaces.UserRepository
	kafkaClient *kafka.Client
	logger      *zap.Logger
}

// NewRoleService создает новый экземпляр RoleService
func NewRoleService(
	roleRepo interfaces.RoleRepository,
	userRepo interfaces.UserRepository,
	kafkaClient *kafka.Client,
	logger *zap.Logger,
) *RoleService {
	return &RoleService{
		roleRepo:    roleRepo,
		userRepo:    userRepo,
		kafkaClient: kafkaClient,
		logger:      logger,
	}
}

// GetRoles получает список всех ролей
func (s *RoleService) GetRoles(ctx context.Context) ([]*models.Role, error) {
	roles, err := s.roleRepo.GetAll(ctx)
	if err != nil {
		s.logger.Error("Failed to get roles", zap.Error(err))
		return nil, err
	}
	return roles, nil
}

// GetRoleByID получает роль по ID
func (s *RoleService) GetRoleByID(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	role, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get role by ID", zap.Error(err), zap.String("role_id", id.String()))
		return nil, err
	}
	return role, nil
}

// GetRoleByName получает роль по имени
func (s *RoleService) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	role, err := s.roleRepo.GetByName(ctx, name)
	if err != nil {
		s.logger.Error("Failed to get role by name", zap.Error(err), zap.String("role_name", name))
		return nil, err
	}
	return role, nil
}

// CreateRole создает новую роль
func (s *RoleService) CreateRole(ctx context.Context, req models.CreateRoleRequest) (*models.Role, error) {
	// Проверка, существует ли роль с таким именем
	existingRole, err := s.roleRepo.GetByName(ctx, req.Name)
	if err == nil && existingRole != nil {
		return nil, models.ErrRoleNameExists
	}

	// Создание роли
	role := &models.Role{
		ID:          uuid.New(),
		Name:        req.Name,
		Description: req.Description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Сохранение роли
	err = s.roleRepo.Create(ctx, role)
	if err != nil {
		s.logger.Error("Failed to create role", zap.Error(err))
		return nil, err
	}

	// Отправка события о создании роли
	event := models.RoleCreatedEvent{
		RoleID:      role.ID.String(),
		Name:        role.Name,
		Description: role.Description,
		CreatedAt:   role.CreatedAt,
	}
	err = s.kafkaClient.PublishRoleEvent(ctx, "role.created", event)
	if err != nil {
		s.logger.Error("Failed to publish role created event", zap.Error(err), zap.String("role_id", role.ID.String()))
	}

	return role, nil
}

// UpdateRole обновляет информацию о роли
func (s *RoleService) UpdateRole(ctx context.Context, id uuid.UUID, req models.UpdateRoleRequest) (*models.Role, error) {
	// Получение роли
	role, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get role for update", zap.Error(err), zap.String("role_id", id.String()))
		return nil, err
	}

	// Проверка, существует ли роль с таким именем
	if req.Name != nil && *req.Name != role.Name {
		existingRole, err := s.roleRepo.GetByName(ctx, *req.Name)
		if err == nil && existingRole != nil && existingRole.ID != id {
			return nil, models.ErrRoleNameExists
		}
		role.Name = *req.Name
	}

	// Обновление описания
	if req.Description != nil {
		role.Description = *req.Description
	}

	// Обновление времени изменения
	role.UpdatedAt = time.Now()

	// Сохранение роли
	err = s.roleRepo.Update(ctx, role)
	if err != nil {
		s.logger.Error("Failed to update role", zap.Error(err), zap.String("role_id", id.String()))
		return nil, err
	}

	// Отправка события об обновлении роли
	event := models.RoleUpdatedEvent{
		RoleID:      role.ID.String(),
		Name:        role.Name,
		Description: role.Description,
		UpdatedAt:   role.UpdatedAt,
	}
	err = s.kafkaClient.PublishRoleEvent(ctx, "role.updated", event)
	if err != nil {
		s.logger.Error("Failed to publish role updated event", zap.Error(err), zap.String("role_id", role.ID.String()))
	}

	return role, nil
}

// DeleteRole удаляет роль
func (s *RoleService) DeleteRole(ctx context.Context, id uuid.UUID) error {
	// Получение роли
	role, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get role for deletion", zap.Error(err), zap.String("role_id", id.String()))
		return err
	}

	// Удаление роли
	err = s.roleRepo.Delete(ctx, id)
	if err != nil {
		s.logger.Error("Failed to delete role", zap.Error(err), zap.String("role_id", id.String()))
		return err
	}

	// Отправка события об удалении роли
	event := models.RoleDeletedEvent{
		RoleID:    role.ID.String(),
		DeletedAt: time.Now(),
	}
	err = s.kafkaClient.PublishRoleEvent(ctx, "role.deleted", event)
	if err != nil {
		s.logger.Error("Failed to publish role deleted event", zap.Error(err), zap.String("role_id", role.ID.String()))
	}

	return nil
}

// AssignRoleToUser назначает роль пользователю
func (s *RoleService) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID) error {
	// Проверка существования пользователя
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for role assignment", zap.Error(err), zap.String("user_id", userID.String()))
		return models.ErrUserNotFound
	}

	// Проверка существования роли
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		s.logger.Error("Failed to get role for assignment", zap.Error(err), zap.String("role_id", roleID.String()))
		return models.ErrRoleNotFound
	}

	// Проверка, назначена ли уже роль пользователю
	hasRole, err := s.roleRepo.UserHasRole(ctx, userID, roleID)
	if err != nil {
		s.logger.Error("Failed to check if user has role", zap.Error(err), zap.String("user_id", userID.String()), zap.String("role_id", roleID.String()))
		return err
	}
	if hasRole {
		return models.ErrRoleAlreadyAssigned
	}

	// Назначение роли пользователю
	err = s.roleRepo.AssignRoleToUser(ctx, userID, roleID)
	if err != nil {
		s.logger.Error("Failed to assign role to user", zap.Error(err), zap.String("user_id", userID.String()), zap.String("role_id", roleID.String()))
		return err
	}

	// Отправка события о назначении роли
	event := models.RoleAssignedEvent{
		UserID:    userID.String(),
		RoleID:    roleID.String(),
		RoleName:  role.Name,
		AssignedAt: time.Now(),
	}
	err = s.kafkaClient.PublishRoleEvent(ctx, "role.assigned", event)
	if err != nil {
		s.logger.Error("Failed to publish role assigned event", zap.Error(err), zap.String("user_id", userID.String()), zap.String("role_id", roleID.String()))
	}

	return nil
}

// RemoveRoleFromUser удаляет роль у пользователя
func (s *RoleService) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	// Проверка существования пользователя
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for role removal", zap.Error(err), zap.String("user_id", userID.String()))
		return models.ErrUserNotFound
	}

	// Проверка существования роли
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		s.logger.Error("Failed to get role for removal", zap.Error(err), zap.String("role_id", roleID.String()))
		return models.ErrRoleNotFound
	}

	// Проверка, назначена ли роль пользователю
	hasRole, err := s.roleRepo.UserHasRole(ctx, userID, roleID)
	if err != nil {
		s.logger.Error("Failed to check if user has role", zap.Error(err), zap.String("user_id", userID.String()), zap.String("role_id", roleID.String()))
		return err
	}
	if !hasRole {
		return models.ErrRoleNotAssigned
	}

	// Удаление роли у пользователя
	err = s.roleRepo.RemoveRoleFromUser(ctx, userID, roleID)
	if err != nil {
		s.logger.Error("Failed to remove role from user", zap.Error(err), zap.String("user_id", userID.String()), zap.String("role_id", roleID.String()))
		return err
	}

	// Отправка события об удалении роли
	event := models.RoleRemovedEvent{
		UserID:    userID.String(),
		RoleID:    roleID.String(),
		RoleName:  role.Name,
		RemovedAt: time.Now(),
	}
	err = s.kafkaClient.PublishRoleEvent(ctx, "role.removed", event)
	if err != nil {
		s.logger.Error("Failed to publish role removed event", zap.Error(err), zap.String("user_id", userID.String()), zap.String("role_id", roleID.String()))
	}

	return nil
}

// GetUserRoles получает роли пользователя
func (s *RoleService) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*models.Role, error) {
	// Проверка существования пользователя
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for roles retrieval", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, models.ErrUserNotFound
	}

	// Получение ролей пользователя
	roles, err := s.roleRepo.GetUserRoles(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user roles", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, err
	}

	return roles, nil
}
