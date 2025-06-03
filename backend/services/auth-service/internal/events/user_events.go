// File: internal/events/handlers/user_events.go

package handlers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/your-org/auth-service/internal/domain/models"
	"github.com/your-org/auth-service/internal/events/kafka"
	"github.com/your-org/auth-service/internal/service"
	"github.com/your-org/auth-service/internal/utils/logger"
)

// UserEventHandler обрабатывает события, связанные с пользователями
type UserEventHandler struct {
	userService  *service.UserService
	authService  *service.AuthService
	tokenService *service.TokenService
	logger       logger.Logger
}

// NewUserEventHandler создает новый обработчик событий пользователей
func NewUserEventHandler(
	userService *service.UserService,
	authService *service.AuthService,
	tokenService *service.TokenService,
	logger logger.Logger,
) *UserEventHandler {
	return &UserEventHandler{
		userService:  userService,
		authService:  authService,
		tokenService: tokenService,
		logger:       logger,
	}
}

// RegisterHandlers регистрирует обработчики событий в потребителе Kafka
func (h *UserEventHandler) RegisterHandlers(consumer *kafka.Consumer) {
	consumer.RegisterHandler("user.created", h.HandleUserCreated)
	consumer.RegisterHandler("user.updated", h.HandleUserUpdated)
	consumer.RegisterHandler("user.deleted", h.HandleUserDeleted)
	consumer.RegisterHandler("user.role_assigned", h.HandleUserRoleAssigned)
	consumer.RegisterHandler("user.role_revoked", h.HandleUserRoleRevoked)
	consumer.RegisterHandler("user.password_changed", h.HandleUserPasswordChanged)
	consumer.RegisterHandler("user.email_verified", h.HandleUserEmailVerified)
	consumer.RegisterHandler("user.account_locked", h.HandleUserAccountLocked)
	consumer.RegisterHandler("user.account_unlocked", h.HandleUserAccountUnlocked)
}

// UserCreatedPayload представляет данные события создания пользователя
type UserCreatedPayload struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	CreatedAt int64  `json:"created_at"`
}

// HandleUserCreated обрабатывает событие создания пользователя
func (h *UserEventHandler) HandleUserCreated(ctx context.Context, event kafka.EventMessage) error {
	var payload UserCreatedPayload
	if err := mapPayload(event.Payload, &payload); err != nil {
		return fmt.Errorf("failed to map payload: %w", err)
	}

	h.logger.Info("Processing user.created event",
		"user_id", payload.UserID,
		"username", payload.Username,
		"email", payload.Email,
	)

	// Здесь может быть логика обработки события создания пользователя
	// Например, отправка приветственного email, создание профиля и т.д.

	return nil
}

// UserUpdatedPayload представляет данные события обновления пользователя
type UserUpdatedPayload struct {
	UserID    string                 `json:"user_id"`
	Changes   map[string]interface{} `json:"changes"`
	UpdatedAt int64                  `json:"updated_at"`
}

// HandleUserUpdated обрабатывает событие обновления пользователя
func (h *UserEventHandler) HandleUserUpdated(ctx context.Context, event kafka.EventMessage) error {
	var payload UserUpdatedPayload
	if err := mapPayload(event.Payload, &payload); err != nil {
		return fmt.Errorf("failed to map payload: %w", err)
	}

	h.logger.Info("Processing user.updated event",
		"user_id", payload.UserID,
		"changes", payload.Changes,
	)

	// Здесь может быть логика обработки события обновления пользователя

	return nil
}

// UserDeletedPayload представляет данные события удаления пользователя
type UserDeletedPayload struct {
	UserID    string `json:"user_id"`
	DeletedAt int64  `json:"deleted_at"`
	Reason    string `json:"reason,omitempty"`
}

// HandleUserDeleted обрабатывает событие удаления пользователя
func (h *UserEventHandler) HandleUserDeleted(ctx context.Context, event kafka.EventMessage) error {
	var payload UserDeletedPayload
	if err := mapPayload(event.Payload, &payload); err != nil {
		return fmt.Errorf("failed to map payload: %w", err)
	}

	h.logger.Info("Processing user.deleted event",
		"user_id", payload.UserID,
		"reason", payload.Reason,
	)

	// Здесь может быть логика обработки события удаления пользователя
	// Например, удаление связанных данных, отзыв всех токенов и т.д.

	// Отзываем все токены пользователя
	if err := h.tokenService.RevokeAllUserTokens(ctx, payload.UserID); err != nil {
		h.logger.Error("Failed to revoke user tokens", "error", err, "user_id", payload.UserID)
		// Не возвращаем ошибку, чтобы продолжить обработку события
	}

	return nil
}

// UserRoleAssignedPayload представляет данные события назначения роли пользователю
type UserRoleAssignedPayload struct {
	UserID    string `json:"user_id"`
	RoleID    string `json:"role_id"`
	RoleName  string `json:"role_name"`
	AssignedAt int64 `json:"assigned_at"`
	AssignedBy string `json:"assigned_by,omitempty"`
}

// HandleUserRoleAssigned обрабатывает событие назначения роли пользователю
func (h *UserEventHandler) HandleUserRoleAssigned(ctx context.Context, event kafka.EventMessage) error {
	var payload UserRoleAssignedPayload
	if err := mapPayload(event.Payload, &payload); err != nil {
		return fmt.Errorf("failed to map payload: %w", err)
	}

	h.logger.Info("Processing user.role_assigned event",
		"user_id", payload.UserID,
		"role_id", payload.RoleID,
		"role_name", payload.RoleName,
	)

	// Здесь может быть логика обработки события назначения роли пользователю

	return nil
}

// UserRoleRevokedPayload представляет данные события отзыва роли у пользователя
type UserRoleRevokedPayload struct {
	UserID    string `json:"user_id"`
	RoleID    string `json:"role_id"`
	RoleName  string `json:"role_name"`
	RevokedAt int64  `json:"revoked_at"`
	RevokedBy string `json:"revoked_by,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// HandleUserRoleRevoked обрабатывает событие отзыва роли у пользователя
func (h *UserEventHandler) HandleUserRoleRevoked(ctx context.Context, event kafka.EventMessage) error {
	var payload UserRoleRevokedPayload
	if err := mapPayload(event.Payload, &payload); err != nil {
		return fmt.Errorf("failed to map payload: %w", err)
	}

	h.logger.Info("Processing user.role_revoked event",
		"user_id", payload.UserID,
		"role_id", payload.RoleID,
		"role_name", payload.RoleName,
	)

	// Здесь может быть логика обработки события отзыва роли у пользователя

	return nil
}

// UserPasswordChangedPayload представляет данные события изменения пароля пользователя
type UserPasswordChangedPayload struct {
	UserID    string `json:"user_id"`
	ChangedAt int64  `json:"changed_at"`
	Forced    bool   `json:"forced,omitempty"`
}

// HandleUserPasswordChanged обрабатывает событие изменения пароля пользователя
func (h *UserEventHandler) HandleUserPasswordChanged(ctx context.Context, event kafka.EventMessage) error {
	var payload UserPasswordChangedPayload
	if err := mapPayload(event.Payload, &payload); err != nil {
		return fmt.Errorf("failed to map payload: %w", err)
	}

	h.logger.Info("Processing user.password_changed event",
		"user_id", payload.UserID,
		"forced", payload.Forced,
	)

	// При изменении пароля отзываем все существующие токены, кроме текущего
	if err := h.tokenService.RevokeAllUserTokensExceptCurrent(ctx, payload.UserID); err != nil {
		h.logger.Error("Failed to revoke user tokens", "error", err, "user_id", payload.UserID)
		// Не возвращаем ошибку, чтобы продолжить обработку события
	}

	return nil
}

// UserEmailVerifiedPayload представляет данные события верификации email пользователя
type UserEmailVerifiedPayload struct {
	UserID     string `json:"user_id"`
	Email      string `json:"email"`
	VerifiedAt int64  `json:"verified_at"`
}

// HandleUserEmailVerified обрабатывает событие верификации email пользователя
func (h *UserEventHandler) HandleUserEmailVerified(ctx context.Context, event kafka.EventMessage) error {
	var payload UserEmailVerifiedPayload
	if err := mapPayload(event.Payload, &payload); err != nil {
		return fmt.Errorf("failed to map payload: %w", err)
	}

	h.logger.Info("Processing user.email_verified event",
		"user_id", payload.UserID,
		"email", payload.Email,
	)

	// Здесь может быть логика обработки события верификации email пользователя

	return nil
}

// UserAccountLockedPayload представляет данные события блокировки аккаунта пользователя
type UserAccountLockedPayload struct {
	UserID    string `json:"user_id"`
	LockedAt  int64  `json:"locked_at"`
	Reason    string `json:"reason,omitempty"`
	LockedBy  string `json:"locked_by,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

// HandleUserAccountLocked обрабатывает событие блокировки аккаунта пользователя
func (h *UserEventHandler) HandleUserAccountLocked(ctx context.Context, event kafka.EventMessage) error {
	var payload UserAccountLockedPayload
	if err := mapPayload(event.Payload, &payload); err != nil {
		return fmt.Errorf("failed to map payload: %w", err)
	}

	h.logger.Info("Processing user.account_locked event",
		"user_id", payload.UserID,
		"reason", payload.Reason,
	)

	// При блокировке аккаунта отзываем все токены пользователя
	if err := h.tokenService.RevokeAllUserTokens(ctx, payload.UserID); err != nil {
		h.logger.Error("Failed to revoke user tokens", "error", err, "user_id", payload.UserID)
		// Не возвращаем ошибку, чтобы продолжить обработку события
	}

	return nil
}

// UserAccountUnlockedPayload представляет данные события разблокировки аккаунта пользователя
type UserAccountUnlockedPayload struct {
	UserID     string `json:"user_id"`
	UnlockedAt int64  `json:"unlocked_at"`
	UnlockedBy string `json:"unlocked_by,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// HandleUserAccountUnlocked обрабатывает событие разблокировки аккаунта пользователя
func (h *UserEventHandler) HandleUserAccountUnlocked(ctx context.Context, event kafka.EventMessage) error {
	var payload UserAccountUnlockedPayload
	if err := mapPayload(event.Payload, &payload); err != nil {
		return fmt.Errorf("failed to map payload: %w", err)
	}

	h.logger.Info("Processing user.account_unlocked event",
		"user_id", payload.UserID,
		"reason", payload.Reason,
	)

	// Здесь может быть логика обработки события разблокировки аккаунта пользователя

	return nil
}

// mapPayload преобразует payload из map[string]interface{} в структуру
func mapPayload(payload interface{}, target interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	return nil
}
