// File: internal/service/user_service.go

package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
	"github.com/your-org/auth-service/internal/repository/interfaces"
	"github.com/your-org/auth-service/internal/utils/kafka"
	"github.com/your-org/auth-service/internal/utils/security"
	"go.uber.org/zap"
)

// UserService предоставляет методы для работы с пользователями
type UserService struct {
	userRepo    interfaces.UserRepository
	roleRepo    interfaces.RoleRepository
	kafkaClient *kafka.Client
	logger      *zap.Logger
}

// NewUserService создает новый экземпляр UserService
func NewUserService(
	userRepo interfaces.UserRepository,
	roleRepo interfaces.RoleRepository,
	kafkaClient *kafka.Client,
	logger *zap.Logger,
) *UserService {
	return &UserService{
		userRepo:    userRepo,
		roleRepo:    roleRepo,
		kafkaClient: kafkaClient,
		logger:      logger,
	}
}

// GetUserByID получает пользователя по ID
func (s *UserService) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get user by ID", zap.Error(err), zap.String("user_id", id.String()))
		return nil, err
	}
	return user, nil
}

// GetUserByEmail получает пользователя по email
func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		s.logger.Error("Failed to get user by email", zap.Error(err), zap.String("email", email))
		return nil, err
	}
	return user, nil
}

// GetUserByUsername получает пользователя по имени пользователя
func (s *UserService) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		s.logger.Error("Failed to get user by username", zap.Error(err), zap.String("username", username))
		return nil, err
	}
	return user, nil
}

// CreateUser создает нового пользователя
func (s *UserService) CreateUser(ctx context.Context, req models.CreateUserRequest) (*models.User, error) {
	// Проверка, существует ли пользователь с таким email
	existingUser, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		return nil, models.ErrEmailExists
	}

	// Проверка, существует ли пользователь с таким именем пользователя
	existingUser, err = s.userRepo.GetByUsername(ctx, req.Username)
	if err == nil && existingUser != nil {
		return nil, models.ErrUsernameExists
	}

	// Хеширование пароля
	hashedPassword, err := security.HashPassword(req.Password)
	if err != nil {
		s.logger.Error("Failed to hash password", zap.Error(err))
		return nil, err
	}

	// Создание пользователя
	user := &models.User{
		ID:             uuid.New(),
		Email:          req.Email,
		Username:       req.Username,
		HashedPassword: hashedPassword,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// Сохранение пользователя
	err = s.userRepo.Create(ctx, user)
	if err != nil {
		s.logger.Error("Failed to create user", zap.Error(err))
		return nil, err
	}

	// Назначение роли "user" по умолчанию
	defaultRole, err := s.roleRepo.GetByName(ctx, "user")
	if err == nil && defaultRole != nil {
		err = s.roleRepo.AssignRoleToUser(ctx, user.ID, defaultRole.ID)
		if err != nil {
			s.logger.Error("Failed to assign default role to user", zap.Error(err), zap.String("user_id", user.ID.String()))
		}
	}

	// Отправка события о создании пользователя
	event := models.UserCreatedEvent{
		UserID:    user.ID.String(),
		Email:     user.Email,
		Username:  user.Username,
		CreatedAt: user.CreatedAt,
	}
	err = s.kafkaClient.PublishUserEvent(ctx, "user.created", event)
	if err != nil {
		s.logger.Error("Failed to publish user created event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}

	return user, nil
}

// UpdateUser обновляет информацию о пользователе
func (s *UserService) UpdateUser(ctx context.Context, id uuid.UUID, req models.UpdateUserRequest) (*models.User, error) {
	// Получение пользователя
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get user for update", zap.Error(err), zap.String("user_id", id.String()))
		return nil, err
	}

	// Проверка, существует ли пользователь с таким email
	if req.Email != nil && *req.Email != user.Email {
		existingUser, err := s.userRepo.GetByEmail(ctx, *req.Email)
		if err == nil && existingUser != nil && existingUser.ID != id {
			return nil, models.ErrEmailExists
		}
		user.Email = *req.Email
	}

	// Проверка, существует ли пользователь с таким именем пользователя
	if req.Username != nil && *req.Username != user.Username {
		existingUser, err := s.userRepo.GetByUsername(ctx, *req.Username)
		if err == nil && existingUser != nil && existingUser.ID != id {
			return nil, models.ErrUsernameExists
		}
		user.Username = *req.Username
	}

	// Обновление времени изменения
	user.UpdatedAt = time.Now()

	// Сохранение пользователя
	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.Error("Failed to update user", zap.Error(err), zap.String("user_id", id.String()))
		return nil, err
	}

	// Отправка события об обновлении пользователя
	event := models.UserUpdatedEvent{
		UserID:    user.ID.String(),
		Email:     user.Email,
		Username:  user.Username,
		UpdatedAt: user.UpdatedAt,
	}
	err = s.kafkaClient.PublishUserEvent(ctx, "user.updated", event)
	if err != nil {
		s.logger.Error("Failed to publish user updated event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}

	return user, nil
}

// DeleteUser удаляет пользователя
func (s *UserService) DeleteUser(ctx context.Context, id uuid.UUID) error {
	// Получение пользователя
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get user for deletion", zap.Error(err), zap.String("user_id", id.String()))
		return err
	}

	// Удаление пользователя
	err = s.userRepo.Delete(ctx, id)
	if err != nil {
		s.logger.Error("Failed to delete user", zap.Error(err), zap.String("user_id", id.String()))
		return err
	}

	// Отправка события об удалении пользователя
	event := models.UserDeletedEvent{
		UserID:    user.ID.String(),
		DeletedAt: time.Now(),
	}
	err = s.kafkaClient.PublishUserEvent(ctx, "user.deleted", event)
	if err != nil {
		s.logger.Error("Failed to publish user deleted event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}

	return nil
}

// ChangePassword изменяет пароль пользователя
func (s *UserService) ChangePassword(ctx context.Context, id uuid.UUID, oldPassword, newPassword string) error {
	// Получение пользователя
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get user for password change", zap.Error(err), zap.String("user_id", id.String()))
		return err
	}

	// Проверка старого пароля
	if !security.CheckPasswordHash(oldPassword, user.HashedPassword) {
		return models.ErrInvalidCredentials
	}

	// Хеширование нового пароля
	hashedPassword, err := security.HashPassword(newPassword)
	if err != nil {
		s.logger.Error("Failed to hash new password", zap.Error(err))
		return err
	}

	// Обновление пароля
	user.HashedPassword = hashedPassword
	user.UpdatedAt = time.Now()

	// Сохранение пользователя
	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.Error("Failed to update user password", zap.Error(err), zap.String("user_id", id.String()))
		return err
	}

	// Отправка события об изменении пароля
	event := models.PasswordChangedEvent{
		UserID:    user.ID.String(),
		UpdatedAt: user.UpdatedAt,
	}
	err = s.kafkaClient.PublishUserEvent(ctx, "user.password_changed", event)
	if err != nil {
		s.logger.Error("Failed to publish password changed event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}

	return nil
}

// GetUserRoles получает роли пользователя
func (s *UserService) GetUserRoles(ctx context.Context, id uuid.UUID) ([]*models.Role, error) {
	// Получение ролей пользователя
	roles, err := s.roleRepo.GetUserRoles(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get user roles", zap.Error(err), zap.String("user_id", id.String()))
		return nil, err
	}
	return roles, nil
}

// HasRole проверяет, имеет ли пользователь указанную роль
func (s *UserService) HasRole(ctx context.Context, id uuid.UUID, roleName string) (bool, error) {
	// Получение ролей пользователя
	roles, err := s.roleRepo.GetUserRoles(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get user roles", zap.Error(err), zap.String("user_id", id.String()))
		return false, err
	}

	// Проверка наличия роли
	for _, role := range roles {
		if role.Name == roleName {
			return true, nil
		}
	}

	return false, nil
}
