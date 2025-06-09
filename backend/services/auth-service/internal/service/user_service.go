// File: internal/service/user_service.go

package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
	domainService "github.com/your-org/auth-service/internal/domain/service" // Ensure this is imported
	"github.com/your-org/auth-service/internal/repository/interfaces"
	// "github.com/your-org/auth-service/internal/utils/kafka" // To be replaced
	eventskafka "github.com/your-org/auth-service/internal/events/kafka" // Sarama-based producer
	"github.com/your-org/auth-service/internal/utils/security"
	"go.uber.org/zap"
)

// UserService предоставляет методы для работы с пользователями
type UserService struct {
	userRepo    interfaces.UserRepository
	roleRepo    interfaces.RoleRepository
	kafkaClient *eventskafka.Producer // Changed to Sarama-based producer
	logger      *zap.Logger
	auditLogRecorder domainService.AuditLogRecorder // Added for audit logging
}

// NewUserService создает новый экземпляр UserService
func NewUserService(
	userRepo interfaces.UserRepository,
	roleRepo interfaces.RoleRepository,
	kafkaClient *eventskafka.Producer, // Changed to Sarama-based producer
	logger *zap.Logger,
	auditLogRecorder domainService.AuditLogRecorder, // Added
) *UserService {
	return &UserService{
		userRepo:    userRepo,
		roleRepo:    roleRepo,
		kafkaClient: kafkaClient, // Assign Sarama-based producer
		logger:      logger,
		auditLogRecorder: auditLogRecorder, // Added
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
// actorID is the ID of the admin/system performing the action. Can be nil.
func (s *UserService) CreateUser(ctx context.Context, req models.CreateUserRequest, actorID *uuid.UUID) (*models.User, error) {
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
	}
	var auditDetails map[string]interface{}

	// Проверка, существует ли пользователь с таким email
	existingUser, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		auditDetails = map[string]interface{}{"error": models.ErrEmailExists.Error(), "email": req.Email}
		s.auditLogRecorder.RecordEvent(ctx, actorID, "admin_user_create", models.AuditLogStatusFailure, nil, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return nil, models.ErrEmailExists
	}

	// Проверка, существует ли пользователь с таким именем пользователя
	existingUser, err = s.userRepo.GetByUsername(ctx, req.Username)
	if err == nil && existingUser != nil {
		auditDetails = map[string]interface{}{"error": models.ErrUsernameExists.Error(), "username": req.Username}
		s.auditLogRecorder.RecordEvent(ctx, actorID, "admin_user_create", models.AuditLogStatusFailure, nil, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return nil, models.ErrUsernameExists
	}

	// Хеширование пароля
	hashedPassword, err := security.HashPassword(req.Password)
	if err != nil {
		s.logger.Error("Failed to hash password", zap.Error(err))
		auditDetails = map[string]interface{}{"error": "password hashing failed", "details": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorID, "admin_user_create", models.AuditLogStatusFailure, nil, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return nil, err
	}

	// Создание пользователя
	newUser := &models.User{ // Renamed to newUser for clarity as target
		ID:             uuid.New(),
		Email:          req.Email,
		Username:       req.Username,
		HashedPassword: hashedPassword,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// Сохранение пользователя
	err = s.userRepo.Create(ctx, newUser)
	if err != nil {
		s.logger.Error("Failed to create user", zap.Error(err))
		auditDetails = map[string]interface{}{"error": "db user creation failed", "details": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorID, "admin_user_create", models.AuditLogStatusFailure, &newUser.ID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return nil, err
	}
	targetUserID := newUser.ID // For audit log

	// Назначение роли "user" по умолчанию
	defaultRole, err := s.roleRepo.GetByName(ctx, "user")
	if err == nil && defaultRole != nil {
		// AssignRoleToUser in RoleService now expects adminUserID.
		// For user creation, this assignment is part of the creation process,
		// so the creator (actorID) is implicitly responsible.
		err = s.roleRepo.AssignRoleToUser(ctx, newUser.ID, defaultRole.ID) // This roleRepo.AssignRoleToUser might be old signature
		// If RoleService.AssignRoleToUser is used, it needs the actorID:
		// err = s.roleService.AssignRoleToUser(ctx, newUser.ID, defaultRole.ID, actorID)
		// For now, assuming roleRepo.AssignRoleToUser is a direct repo call not needing actor.
		if err != nil {
			s.logger.Error("Failed to assign default role to user", zap.Error(err), zap.String("user_id", newUser.ID.String()))
			// Log as warning with success, as user creation succeeded.
			auditDetails = map[string]interface{}{"warning": "failed to assign default role", "role_id": defaultRole.ID, "error": err.Error()}
		}
	}

	// Отправка события о создании пользователя
	event := models.UserCreatedEvent{
		UserID:    newUser.ID.String(),
		Email:     newUser.Email,
		Username:  newUser.Username,
		CreatedAt: newUser.CreatedAt,
	}
	// Map to new CloudEvent payload UserRegisteredPayload
	// Assuming UserRegisteredPayload is now in models package
	userRegisteredPayload := models.UserRegisteredPayload{
		UserID:                newUser.ID.String(),
		Username:              newUser.Username,
		Email:                 newUser.Email,
		DisplayName:           nil, // UserService.CreateUser doesn't handle display name
		RegistrationTimestamp: newUser.CreatedAt,
		InitialStatus:         string(models.UserStatusActive), // Assuming admin creation implies active
	}
	subjectUserCreated := newUser.ID.String()
	contentTypeJSON := "application/json"
	// TODO: Determine correct topic. Using placeholder "auth-events".
	// Also, confirm if AuthUserRegisteredV1 is the correct type or if an admin-specific one is needed.
	// Assuming eventModels.AuthUserRegisteredV1 is now models.AuthUserRegisteredV1
	if err := s.kafkaClient.PublishCloudEvent( // Corrected s.kafkaProducer to s.kafkaClient
		ctx,
		"auth-events", // topic
		eventskafka.EventType(models.AuthUserRegisteredV1), // eventType
		&subjectUserCreated, // subject
		&contentTypeJSON,    // dataContentType
		userRegisteredPayload, // dataPayload
	); err != nil {
		s.logger.Error("Failed to publish CloudEvent for user created/registered", zap.Error(err), zap.String("user_id", newUser.ID.String()))
		if auditDetails == nil { auditDetails = make(map[string]interface{}) }
		auditDetails["warning_cloudevent_publish"] = err.Error()
	}

	s.auditLogRecorder.RecordEvent(ctx, actorID, "admin_user_create", models.AuditLogStatusSuccess, &targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	return newUser, nil
}

// UpdateUser обновляет информацию о пользователе
// actorID is the ID of the admin or the user themselves if it's a self-profile update.
func (s *UserService) UpdateUser(ctx context.Context, id uuid.UUID, req models.UpdateUserRequest, actorID *uuid.UUID) (*models.User, error) {
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
	}
	var auditDetails = make(map[string]interface{})
	var changedFields []string
	targetUserID := &id

	// Получение пользователя
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get user for update", zap.Error(err), zap.String("user_id", id.String()))
		auditDetails["error"] = "user not found for update"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorID, "user_update_profile", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return nil, err
	}

	// Проверка, существует ли пользователь с таким email
	if req.Email != nil && *req.Email != user.Email {
		existingUser, err := s.userRepo.GetByEmail(ctx, *req.Email)
		if err == nil && existingUser != nil && existingUser.ID != id {
			auditDetails["error"] = models.ErrEmailExists.Error()
			auditDetails["attempted_email"] = *req.Email
			s.auditLogRecorder.RecordEvent(ctx, actorID, "user_update_profile", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return nil, models.ErrEmailExists
		}
		user.Email = *req.Email
		changedFields = append(changedFields, "email")
	}

	// Проверка, существует ли пользователь с таким именем пользователя
	if req.Username != nil && *req.Username != user.Username {
		existingUser, err := s.userRepo.GetByUsername(ctx, *req.Username)
		if err == nil && existingUser != nil && existingUser.ID != id {
			auditDetails["error"] = models.ErrUsernameExists.Error()
			auditDetails["attempted_username"] = *req.Username
			s.auditLogRecorder.RecordEvent(ctx, actorID, "user_update_profile", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return nil, models.ErrUsernameExists
		}
		user.Username = *req.Username
		changedFields = append(changedFields, "username")
	}

	// Add other updatable profile fields here if any (e.g., FullName, ProfilePictureURL)
	// For example:
	// if req.FullName != nil && *req.FullName != user.FullName {
	// 	user.FullName = *req.FullName
	//  changedFields = append(changedFields, "full_name")
	// }

	if len(changedFields) == 0 {
		// No actual changes provided, but log an attempt if desired, or just return.
		// For now, just return the user. If this is an error, it should be handled.
		// Or, log success with "no_changes" in details.
		auditDetails["info"] = "no fields to update"
		s.auditLogRecorder.RecordEvent(ctx, actorID, "user_update_profile", models.AuditLogStatusSuccess, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return user, nil
	}

	auditDetails["changed_fields"] = changedFields
	user.UpdatedAt = time.Now()

	// Сохранение пользователя
	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.Error("Failed to update user", zap.Error(err), zap.String("user_id", id.String()))
		auditDetails["error"] = "db user update failed"
		auditDetails["db_error_details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorID, "user_update_profile", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return nil, err
	}

	// Отправка события об обновлении пользователя
	event := models.UserUpdatedEvent{
		UserID:    user.ID.String(),
		Email:     user.Email,
		Username:  user.Username,
		UpdatedAt: user.UpdatedAt,
	}
	// Map to new CloudEvent Payload
	// Assuming UserProfileUpdatedPayload is now in models package
	userProfileUpdatedPayload := models.UserProfileUpdatedPayload{
		UserID:        user.ID.String(),
		UpdatedAt:     user.UpdatedAt,
		ChangedFields: changedFields, // Captured earlier in the method
	}
	if actorID != nil {
		actorIDStr := actorID.String()
		userProfileUpdatedPayload.ActorID = &actorIDStr
	}
	subjectUserProfileUpdated := user.ID.String()
	contentTypeJSON := "application/json"
	// TODO: Determine correct topic
	// Assuming eventModels.AuthUserProfileUpdatedV1 is now models.AuthUserProfileUpdatedV1
	if err := s.kafkaClient.PublishCloudEvent( // Corrected s.kafkaProducer to s.kafkaClient
		ctx,
		"auth-events", // topic
		eventskafka.EventType(models.AuthUserProfileUpdatedV1), // eventType
		&subjectUserProfileUpdated, // subject
		&contentTypeJSON,           // dataContentType
		userProfileUpdatedPayload,  // dataPayload
	); err != nil {
		s.logger.Error("Failed to publish CloudEvent for user profile updated", zap.Error(err), zap.String("user_id", user.ID.String()))
		if auditDetails == nil { auditDetails = make(map[string]interface{}) }
		auditDetails["warning_cloudevent_publish"] = err.Error()
	}

	s.auditLogRecorder.RecordEvent(ctx, actorID, "user_update_profile", models.AuditLogStatusSuccess, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	return user, nil
}

// DeleteUser удаляет пользователя (предполагается soft delete)
// actorID is the ID of the admin performing the action.
func (s *UserService) DeleteUser(ctx context.Context, id uuid.UUID, actorID *uuid.UUID) error {
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
	}
	var auditDetails = make(map[string]interface{})
	targetUserID := &id

	// Получение пользователя (опционально, для логгирования деталей или проверки)
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get user for deletion", zap.Error(err), zap.String("user_id", id.String()))
		// If user not found, it might be acceptable for a delete operation depending on idempotency requirements.
		// For now, let's log it as a failure to find.
		auditDetails["error"] = "user not found for deletion"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorID, "admin_user_delete", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return err
	}

	// Удаление пользователя (предполагается, что userRepo.Delete выполняет soft delete)
	err = s.userRepo.Delete(ctx, id)
	if err != nil {
		s.logger.Error("Failed to delete user", zap.Error(err), zap.String("user_id", id.String()))
		auditDetails["error"] = "db user delete failed"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorID, "admin_user_delete", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return err
	}

	// Отправка события об удалении пользователя
	deactivatedAt := time.Now()
	// If userRepo.Delete is a soft delete, it might set user.DeletedAt or user.Status.
	// We'll use `deactivatedAt` for the event timestamp.
	userAccountDeactivatedPayload := eventModels.UserAccountDeactivatedPayload{
		UserID:        user.ID.String(),
		DeactivatedAt: deactivatedAt,
	}
	if actorID != nil {
		actorIDStr := actorID.String()
		userAccountDeactivatedPayload.ActorID = &actorIDStr
	}
	subjectUserDeactivated := user.ID.String()
	contentTypeJSON := "application/json"
	// TODO: Determine correct topic. Using placeholder "auth-events".
	// Assuming eventModels.AuthUserAccountDeactivatedV1 is now models.AuthUserAccountDeactivatedV1
	if err := s.kafkaClient.PublishCloudEvent( // Corrected s.kafkaProducer to s.kafkaClient
		ctx,
		"auth-events", // topic
		eventskafka.EventType(models.AuthUserAccountDeactivatedV1), // eventType
		&subjectUserDeactivated, // subject
		&contentTypeJSON,        // dataContentType
		userAccountDeactivatedPayload, // dataPayload
	); err != nil {
		s.logger.Error("Failed to publish CloudEvent for user deactivated", zap.Error(err), zap.String("user_id", user.ID.String()))
		if auditDetails == nil { auditDetails = make(map[string]interface{}) }
		auditDetails["warning_cloudevent_publish"] = err.Error()
	}

	s.auditLogRecorder.RecordEvent(ctx, actorID, "admin_user_delete", models.AuditLogStatusSuccess, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
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
		UserID:    user.ID.String(),
		UpdatedAt: user.UpdatedAt,
	}
	// Map to new CloudEvent Payload
	// Assuming UserPasswordChangedPayload is now in models package
	passwordChangedPayload := models.UserPasswordChangedPayload{
		UserID:    user.ID.String(),
		ChangedAt: user.UpdatedAt, // user.UpdatedAt was set to time.Now() before this
		Source:    "user_self_service", // Assuming this ChangePassword is self-service
	}
	subjectPasswordChanged := user.ID.String()
	contentTypeJSON := "application/json"
	// TODO: Determine correct topic. Using placeholder "auth-events".
	// Assuming eventModels.AuthUserPasswordChangedV1 is now models.AuthUserPasswordChangedV1
	if err := s.kafkaClient.PublishCloudEvent( // Corrected s.kafkaProducer to s.kafkaClient
		ctx,
		"auth-events", // topic
		eventskafka.EventType(models.AuthUserPasswordChangedV1), // eventType
		&subjectPasswordChanged, // subject
		&contentTypeJSON,        // dataContentType
		passwordChangedPayload,  // dataPayload
	); err != nil {
		s.logger.Error("Failed to publish CloudEvent for password changed", zap.Error(err), zap.String("user_id", user.ID.String()))
		// Not returning error for this, but logging it.
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

// BlockUser блокирует пользователя (административное действие)
// actorID is the ID of the admin performing the action.
// reason is an optional field for why the user is being blocked.
func (s *UserService) BlockUser(ctx context.Context, id uuid.UUID, actorID *uuid.UUID, reason string) error {
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
	}
	var auditDetails = make(map[string]interface{})
	targetUserID := &id
	if reason != "" {
		auditDetails["reason"] = reason
	}

	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get user for blocking", zap.Error(err), zap.String("user_id", id.String()))
		auditDetails["error"] = "user not found for blocking"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorID, "admin_user_block", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return err
	}

	// В репозитории userRepo должен быть метод для обновления статуса, например UpdateStatus
	// Либо получаем пользователя, меняем статус и вызываем userRepo.Update(ctx, user)
	user.Status = models.UserStatusBlocked
	// user.StatusReason = reason // If you have such a field
	user.UpdatedAt = time.Now()

	err = s.userRepo.Update(ctx, user) // Assuming Update handles status changes
	if err != nil {
		s.logger.Error("Failed to block user (update status)", zap.Error(err), zap.String("user_id", id.String()))
		auditDetails["error"] = "db user block failed"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorID, "admin_user_block", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return err
	}

	blockedAt := time.Now()
	// Assuming UserAccountBlockedPayload is now in models package
	userBlockedPayload := models.UserAccountBlockedPayload{
		UserID:    id.String(),
		BlockedAt: blockedAt,
	}
	if reason != "" {
		userBlockedPayload.Reason = &reason
	}
	if actorID != nil {
		actorIDStr := actorID.String()
		userBlockedPayload.ActorID = &actorIDStr
	}
	subjectUserBlocked := id.String()
	contentTypeJSON := "application/json"
	// TODO: Determine correct topic
	// Assuming eventModels.AuthUserAccountBlockedV1 is now models.AuthUserAccountBlockedV1
	if err := s.kafkaClient.PublishCloudEvent( // Corrected s.kafkaProducer to s.kafkaClient
		ctx,
		"auth-events", // topic
		eventskafka.EventType(models.AuthUserAccountBlockedV1), // eventType
		&subjectUserBlocked, // subject
		&contentTypeJSON,    // dataContentType
		userBlockedPayload,  // dataPayload
	); err != nil {
		s.logger.Error("Failed to publish CloudEvent for user blocked", zap.Error(err), zap.String("user_id", id.String()))
		if auditDetails == nil { auditDetails = make(map[string]interface{}) }
		auditDetails["warning_cloudevent_publish"] = err.Error()
	}

	s.auditLogRecorder.RecordEvent(ctx, actorID, "admin_user_block", models.AuditLogStatusSuccess, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	return nil
}

// UnblockUser разблокирует пользователя (административное действие)
// actorID is the ID of the admin performing the action.
func (s *UserService) UnblockUser(ctx context.Context, id uuid.UUID, actorID *uuid.UUID) error {
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
	}
	var auditDetails = make(map[string]interface{})
	targetUserID := &id

	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get user for unblocking", zap.Error(err), zap.String("user_id", id.String()))
		auditDetails["error"] = "user not found for unblocking"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorID, "admin_user_unblock", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return err
	}

	if user.Status != models.UserStatusBlocked {
		// Optional: Log or return error if user is not currently blocked
		auditDetails["info"] = "user was not blocked"
		// Potentially return an error like domainErrors.ErrUserNotBlocked
	}

	user.Status = models.UserStatusActive // Or whatever the default active status is
	// user.StatusReason = "" // Clear reason if you have one
	user.UpdatedAt = time.Now()

	err = s.userRepo.Update(ctx, user) // Assuming Update handles status changes
	if err != nil {
		s.logger.Error("Failed to unblock user (update status)", zap.Error(err), zap.String("user_id", id.String()))
		auditDetails["error"] = "db user unblock failed"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorID, "admin_user_unblock", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return err
	}

	unblockedAt := time.Now()
	// Assuming UserAccountUnblockedPayload is now in models package
	userUnblockedPayload := models.UserAccountUnblockedPayload{
		UserID:      id.String(),
		UnblockedAt: unblockedAt,
	}
	if actorID != nil {
		actorIDStr := actorID.String()
		userUnblockedPayload.ActorID = &actorIDStr
	}
	subjectUserUnblocked := id.String()
	contentTypeJSON := "application/json"
	// TODO: Determine correct topic
	// Assuming eventModels.AuthUserAccountUnblockedV1 is now models.AuthUserAccountUnblockedV1
	if err := s.kafkaClient.PublishCloudEvent( // Corrected s.kafkaProducer to s.kafkaClient
		ctx,
		"auth-events", // topic
		eventskafka.EventType(models.AuthUserAccountUnblockedV1), // eventType
		&subjectUserUnblocked, // subject
		&contentTypeJSON,      // dataContentType
		userUnblockedPayload,  // dataPayload
	); err != nil {
		s.logger.Error("Failed to publish CloudEvent for user unblocked", zap.Error(err), zap.String("user_id", id.String()))
		if auditDetails == nil { auditDetails = make(map[string]interface{}) }
		auditDetails["warning_cloudevent_publish"] = err.Error()
	}

	s.auditLogRecorder.RecordEvent(ctx, actorID, "admin_user_unblock", models.AuditLogStatusSuccess, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	return nil
}
