// File: internal/events/handlers/account_events.go

package handlers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/your-org/auth-service/internal/events/kafka"
	"github.com/your-org/auth-service/internal/service"
	"github.com/your-org/auth-service/internal/utils/logger"
)

// AccountEventHandler обрабатывает события, связанные с аккаунтами
type AccountEventHandler struct {
	authService  *service.AuthService
	tokenService *service.TokenService
	sessionService *service.SessionService
	logger       logger.Logger
}

// NewAccountEventHandler создает новый обработчик событий аккаунтов
func NewAccountEventHandler(
	authService *service.AuthService,
	tokenService *service.TokenService,
	sessionService *service.SessionService,
	logger logger.Logger,
) *AccountEventHandler {
	return &AccountEventHandler{
		authService:  authService,
		tokenService: tokenService,
		sessionService: sessionService,
		logger:       logger,
	}
}

// RegisterHandlers регистрирует обработчики событий в потребителе Kafka
func (h *AccountEventHandler) RegisterHandlers(consumer *kafka.Consumer) {
	consumer.RegisterHandler("account.login", h.HandleAccountLogin)
	consumer.RegisterHandler("account.logout", h.HandleAccountLogout)
	consumer.RegisterHandler("account.token_refreshed", h.HandleAccountTokenRefreshed)
	consumer.RegisterHandler("account.password_reset_requested", h.HandleAccountPasswordResetRequested)
	consumer.RegisterHandler("account.password_reset_completed", h.HandleAccountPasswordResetCompleted)
	consumer.RegisterHandler("account.two_factor_enabled", h.HandleAccountTwoFactorEnabled)
	consumer.RegisterHandler("account.two_factor_disabled", h.HandleAccountTwoFactorDisabled)
	consumer.RegisterHandler("account.telegram_linked", h.HandleAccountTelegramLinked)
	consumer.RegisterHandler("account.telegram_unlinked", h.HandleAccountTelegramUnlinked)
}

// AccountLoginPayload представляет данные события входа в аккаунт
type AccountLoginPayload struct {
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	LoginAt   int64  `json:"login_at"`
	Success   bool   `json:"success"`
	FailReason string `json:"fail_reason,omitempty"`
}

// HandleAccountLogin обрабатывает событие входа в аккаунт
func (h *AccountEventHandler) HandleAccountLogin(ctx context.Context, event kafka.EventMessage) error {
	var payload AccountLoginPayload
	if err := mapPayload(event.Payload, &payload); err != nil {
		return fmt.Errorf("failed to map payload: %w", err)
	}

	h.logger.Info("Processing account.login event",
		"user_id", payload.UserID,
		"session_id", payload.SessionID,
		"ip", payload.IP,
		"success", payload.Success,
	)

	// Здесь может быть логика обработки события входа в аккаунт
	// Например, обновление статистики входов, проверка подозрительной активности и т.д.

	return nil
}

// AccountLogoutPayload представляет данные события выхода из аккаунта
type AccountLogoutPayload struct {
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
	LogoutAt  int64  `json:"logout_at"`
	Reason    string `json:"reason,omitempty"`
}

// HandleAccountLogout обрабатывает событие выхода из аккаунта
func (h *AccountEventHandler) HandleAccountLogout(ctx context.Context, event kafka.EventMessage) error {
	var payload AccountLogoutPayload
	if err := mapPayload(event.Payload, &payload); err != nil {
		return fmt.Errorf("failed to map payload: %w", err)
	}

	h.logger.Info("Processing account.logout event",
		"user_id", payload.UserID,
		"session_id", payload.SessionID,
	)

	// Здесь может быть логика обработки события выхода из аккаунта

	return nil
}

// AccountTokenRefreshedPayload представляет данные события обновления токена
type AccountTokenRefreshedPayload struct {
	UserID      string `json:"user_id"`
	SessionID   string `json:"session_id"`
	OldTokenID  string `json:"old_token_id"`
	NewTokenID  string `json:"new_token_id"`
	RefreshedAt int64  `json:"refreshed_at"`
	IP          string `json:"ip"`
	UserAgent   string `json:"user_agent"`
}

// HandleAccountTokenRefreshed обрабатывает событие обновления токена
func (h *AccountEventHandler) HandleAccountTokenRefreshed(ctx context.Context, event kafka.EventMessage) error {
	var payload AccountTokenRefreshedPayload
	if err := mapPayload(event.Payload, &payload); err != nil {
		return fmt.Errorf("failed to map payload: %w", err)
	}

	h.logger.Info("Processing account.token_refreshed event",
		"user_id", payload.UserID,
		"session_id", payload.SessionID,
		"old_token_id", payload.OldTokenID,
		"new_token_id", payload.NewTokenID,
	)

	// Здесь может быть логика обработки события обновления токена

	return nil
}

// AccountPasswordResetRequestedPayload представляет данные события запроса сброса пароля
type AccountPasswordResetRequestedPayload struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	ResetCode string `json:"reset_code"`
	RequestedAt int64 `json:"requested_at"`
	ExpiresAt int64  `json:"expires_at"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
}

// HandleAccountPasswordResetRequested обрабатывает событие запроса сброса пароля
func (h *AccountEventHandler) HandleAccountPasswordResetRequested(ctx context.Context, event kafka.EventMessage) error {
	var payload AccountPasswordResetRequestedPayload
	if err := mapPayload(event.Payload, &payload); err != nil {
		return fmt.Errorf("failed to map payload: %w", err)
	}

	h.logger.Info("Processing account.password_reset_requested event",
		"user_id", payload.UserID,
		"email", payload.Email,
	)

	// Здесь может быть логика обработки события запроса сброса пароля
	// Например, отправка email с кодом сброса пароля

	return nil
}

// AccountPasswordResetCompletedPayload представляет данные события завершения сброса пароля
type AccountPasswordResetCompletedPayload struct {
	UserID     string `json:"user_id"`
	Email      string `json:"email"`
	CompletedAt int64 `json:"completed_at"`
	IP         string `json:"ip"`
	UserAgent  string `json:"user_agent"`
	Success    bool   `json:"success"`
	FailReason string `json:"fail_reason,omitempty"`
}

// HandleAccountPasswordResetCompleted обрабатывает событие завершения сброса пароля
func (h *AccountEventHandler) HandleAccountPasswordResetCompleted(ctx context.Context, event kafka.EventMessage) error {
	var payload AccountPasswordResetCompletedPayload
	if err := mapPayload(event.Payload, &payload); err != nil {
		return fmt.Errorf("failed to map payload: %w", err)
	}

	h.logger.Info("Processing account.password_reset_completed event",
		"user_id", payload.UserID,
		"email", payload.Email,
		"success", payload.Success,
	)

	// При успешном сбросе пароля отзываем все токены пользователя
	if payload.Success {
		if err := h.tokenService.RevokeAllUserTokens(ctx, payload.UserID); err != nil {
			h.logger.Error("Failed to revoke user tokens", "error", err, "user_id", payload.UserID)
			// Не возвращаем ошибку, чтобы продолжить обработку события
		}
	}

	return nil
}

// AccountTwoFactorEnabledPayload представляет данные события включения двухфакторной аутентификации
type AccountTwoFactorEnabledPayload struct {
	UserID    string `json:"user_id"`
	EnabledAt int64  `json:"enabled_at"`
	Method    string `json:"method"` // "totp", "sms", etc.
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
}

// HandleAccountTwoFactorEnabled обрабатывает событие включения двухфакторной аутентификации
func (h *AccountEventHandler) HandleAccountTwoFactorEnabled(ctx context.Context, event kafka.EventMessage) error {
	var payload AccountTwoFactorEnabledPayload
	if err := mapPayload(event.Payload, &payload); err != nil {
		return fmt.Errorf("failed to map payload: %w", err)
	}

	h.logger.Info("Processing account.two_factor_enabled event",
		"user_id", payload.UserID,
		"method", payload.Method,
	)

	// Здесь может быть логика обработки события включения двухфакторной аутентификации

	return nil
}

// AccountTwoFactorDisabledPayload представляет данные события отключения двухфакторной аутентификации
type AccountTwoFactorDisabledPayload struct {
	UserID     string `json:"user_id"`
	DisabledAt int64  `json:"disabled_at"`
	Method     string `json:"method"` // "totp", "sms", etc.
	IP         string `json:"ip"`
	UserAgent  string `json:"user_agent"`
	Reason     string `json:"reason,omitempty"`
}

// HandleAccountTwoFactorDisabled обрабатывает событие отключения двухфакторной аутентификации
func (h *AccountEventHandler) HandleAccountTwoFactorDisabled(ctx context.Context, event kafka.EventMessage) error {
	var payload AccountTwoFactorDisabledPayload
	if err := mapPayload(event.Payload, &payload); err != nil {
		return fmt.Errorf("failed to map payload: %w", err)
	}

	h.logger.Info("Processing account.two_factor_disabled event",
		"user_id", payload.UserID,
		"method", payload.Method,
	)

	// Здесь может быть логика обработки события отключения двухфакторной аутентификации

	return nil
}

// AccountTelegramLinkedPayload представляет данные события привязки Telegram
type AccountTelegramLinkedPayload struct {
	UserID       string `json:"user_id"`
	TelegramID   string `json:"telegram_id"`
	TelegramName string `json:"telegram_name"`
	LinkedAt     int64  `json:"linked_at"`
	IP           string `json:"ip"`
	UserAgent    string `json:"user_agent"`
}

// HandleAccountTelegramLinked обрабатывает событие привязки Telegram
func (h *AccountEventHandler) HandleAccountTelegramLinked(ctx context.Context, event kafka.EventMessage) error {
	var payload AccountTelegramLinkedPayload
	if err := mapPayload(event.Payload, &payload); err != nil {
		return fmt.Errorf("failed to map payload: %w", err)
	}

	h.logger.Info("Processing account.telegram_linked event",
		"user_id", payload.UserID,
		"telegram_id", payload.TelegramID,
		"telegram_name", payload.TelegramName,
	)

	// Здесь может быть логика обработки события привязки Telegram

	return nil
}

// AccountTelegramUnlinkedPayload представляет данные события отвязки Telegram
type AccountTelegramUnlinkedPayload struct {
	UserID       string `json:"user_id"`
	TelegramID   string `json:"telegram_id"`
	TelegramName string `json:"telegram_name"`
	UnlinkedAt   int64  `json:"unlinked_at"`
	IP           string `json:"ip"`
	UserAgent    string `json:"user_agent"`
	Reason       string `json:"reason,omitempty"`
}

// HandleAccountTelegramUnlinked обрабатывает событие отвязки Telegram
func (h *AccountEventHandler) HandleAccountTelegramUnlinked(ctx context.Context, event kafka.EventMessage) error {
	var payload AccountTelegramUnlinkedPayload
	if err := mapPayload(event.Payload, &payload); err != nil {
		return fmt.Errorf("failed to map payload: %w", err)
	}

	h.logger.Info("Processing account.telegram_unlinked event",
		"user_id", payload.UserID,
		"telegram_id", payload.TelegramID,
		"telegram_name", payload.TelegramName,
	)

	// Здесь может быть логика обработки события отвязки Telegram

	return nil
}
