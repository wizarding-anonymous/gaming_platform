// File: internal/events/publisher/publisher.go

package publisher

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/events/kafka"
	"github.com/your-org/auth-service/internal/events/models"
	"github.com/your-org/auth-service/internal/utils/logger"
)

// Publisher представляет интерфейс для публикации событий
type Publisher struct {
	producer kafka.Producer
	logger   logger.Logger
	config   *config.EventConfig
	source   string
}

// NewPublisher создает новый экземпляр издателя событий
func NewPublisher(producer kafka.Producer, logger logger.Logger, config *config.EventConfig) *Publisher {
	return &Publisher{
		producer: producer,
		logger:   logger,
		config:   config,
		source:   "auth-service",
	}
}

// Publish публикует событие
func (p *Publisher) Publish(ctx context.Context, eventType models.EventType, data interface{}) error {
	// Если события отключены, ничего не делаем
	if !p.config.Enabled {
		return nil
	}

	// Создаем новое событие
	event := models.Event{
		ID:      uuid.New().String(),
		Type:    eventType,
		Source:  p.source,
		Time:    time.Now().UTC(),
	}

	// Преобразуем данные в map[string]interface{}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		p.logger.Error("Failed to marshal event data", "error", err, "event_type", eventType)
		return fmt.Errorf("failed to marshal event data: %w", err)
	}

	var dataMap map[string]interface{}
	if err := json.Unmarshal(dataBytes, &dataMap); err != nil {
		p.logger.Error("Failed to unmarshal event data", "error", err, "event_type", eventType)
		return fmt.Errorf("failed to unmarshal event data: %w", err)
	}

	// Устанавливаем данные события
	event.Data = dataMap

	// Устанавливаем дополнительные поля в зависимости от типа события
	if userID, ok := dataMap["user_id"].(string); ok {
		event.UserID = userID
		event.Subject = userID
		event.SubjectType = "user"
	}

	if sessionID, ok := dataMap["session_id"].(string); ok {
		event.SessionID = sessionID
	}

	if ip, ok := dataMap["ip"].(string); ok {
		event.IP = ip
	}

	if userAgent, ok := dataMap["user_agent"].(string); ok {
		event.UserAgent = userAgent
	}

	// Определяем топик Kafka в зависимости от типа события
	topic := p.getTopicForEventType(eventType)

	// Сериализуем событие в JSON
	eventBytes, err := json.Marshal(event)
	if err != nil {
		p.logger.Error("Failed to marshal event", "error", err, "event_type", eventType)
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Публикуем событие в Kafka
	err = p.producer.Produce(ctx, topic, event.ID, eventBytes)
	if err != nil {
		p.logger.Error("Failed to produce event", "error", err, "event_type", eventType, "topic", topic)
		return fmt.Errorf("failed to produce event: %w", err)
	}

	p.logger.Info("Event published", "event_id", event.ID, "event_type", eventType, "topic", topic)
	return nil
}

// PublishUserCreated публикует событие создания пользователя
func (p *Publisher) PublishUserCreated(ctx context.Context, userID, username, email string) error {
	event := models.UserCreatedEvent{
		UserID:    userID,
		Username:  username,
		Email:     email,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	return p.Publish(ctx, models.UserCreated, event)
}

// PublishUserUpdated публикует событие обновления пользователя
func (p *Publisher) PublishUserUpdated(ctx context.Context, userID string, changes map[string]interface{}) error {
	event := models.UserUpdatedEvent{
		UserID:    userID,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Changes:   changes,
	}
	return p.Publish(ctx, models.UserUpdated, event)
}

// PublishUserDeleted публикует событие удаления пользователя
func (p *Publisher) PublishUserDeleted(ctx context.Context, userID, username, email string) error {
	event := models.UserDeletedEvent{
		UserID:    userID,
		Username:  username,
		Email:     email,
		DeletedAt: time.Now().UTC().Format(time.RFC3339),
	}
	return p.Publish(ctx, models.UserDeleted, event)
}

// PublishUserPasswordChanged публикует событие изменения пароля пользователя
func (p *Publisher) PublishUserPasswordChanged(ctx context.Context, userID, ip, userAgent string) error {
	event := models.UserPasswordChangedEvent{
		UserID:    userID,
		ChangedAt: time.Now().UTC().Format(time.RFC3339),
		IP:        ip,
		UserAgent: userAgent,
	}
	return p.Publish(ctx, models.UserPasswordChanged, event)
}

// PublishUserEmailVerified публикует событие подтверждения email пользователя
func (p *Publisher) PublishUserEmailVerified(ctx context.Context, userID, email string) error {
	event := models.UserEmailVerifiedEvent{
		UserID:     userID,
		Email:      email,
		VerifiedAt: time.Now().UTC().Format(time.RFC3339),
	}
	return p.Publish(ctx, models.UserEmailVerified, event)
}

// PublishUserLoginSuccess публикует событие успешного входа пользователя
func (p *Publisher) PublishUserLoginSuccess(ctx context.Context, userID, username, ip, userAgent, location string) error {
	event := models.UserLoginSuccessEvent{
		UserID:    userID,
		Username:  username,
		IP:        ip,
		UserAgent: userAgent,
		LoginAt:   time.Now().UTC().Format(time.RFC3339),
		Location:  location,
	}
	return p.Publish(ctx, models.UserLoginSuccess, event)
}

// PublishUserLoginFailed публикует событие неудачного входа пользователя
func (p *Publisher) PublishUserLoginFailed(ctx context.Context, username, ip, userAgent, reason, location string) error {
	event := models.UserLoginFailedEvent{
		Username:  username,
		IP:        ip,
		UserAgent: userAgent,
		Reason:    reason,
		FailedAt:  time.Now().UTC().Format(time.RFC3339),
		Location:  location,
	}
	return p.Publish(ctx, models.UserLoginFailed, event)
}

// PublishUserLogout публикует событие выхода пользователя
func (p *Publisher) PublishUserLogout(ctx context.Context, userID, sessionID, ip, userAgent string) error {
	event := models.UserLogoutEvent{
		UserID:    userID,
		SessionID: sessionID,
		IP:        ip,
		UserAgent: userAgent,
		LogoutAt:  time.Now().UTC().Format(time.RFC3339),
	}
	return p.Publish(ctx, models.UserLogout, event)
}

// PublishSessionCreated публикует событие создания сессии
func (p *Publisher) PublishSessionCreated(ctx context.Context, sessionID, userID, ip, userAgent, location string, expiresAt time.Time) error {
	event := models.SessionCreatedEvent{
		SessionID: sessionID,
		UserID:    userID,
		IP:        ip,
		UserAgent: userAgent,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		ExpiresAt: expiresAt.Format(time.RFC3339),
		Location:  location,
	}
	return p.Publish(ctx, models.SessionCreated, event)
}

// PublishSessionExpired публикует событие истечения сессии
func (p *Publisher) PublishSessionExpired(ctx context.Context, sessionID, userID string) error {
	event := models.SessionExpiredEvent{
		SessionID: sessionID,
		UserID:    userID,
		ExpiredAt: time.Now().UTC().Format(time.RFC3339),
	}
	return p.Publish(ctx, models.SessionExpired, event)
}

// PublishSessionRevoked публикует событие отзыва сессии
func (p *Publisher) PublishSessionRevoked(ctx context.Context, sessionID, userID, revokedBy, reason string) error {
	event := models.SessionRevokedEvent{
		SessionID: sessionID,
		UserID:    userID,
		RevokedBy: revokedBy,
		Reason:    reason,
		RevokedAt: time.Now().UTC().Format(time.RFC3339),
	}
	return p.Publish(ctx, models.SessionRevoked, event)
}

// PublishTokenCreated публикует событие создания токена
func (p *Publisher) PublishTokenCreated(ctx context.Context, tokenID, userID, tokenType, ip, userAgent string, expiresAt time.Time) error {
	event := models.TokenCreatedEvent{
		TokenID:   tokenID,
		UserID:    userID,
		TokenType: tokenType,
		IP:        ip,
		UserAgent: userAgent,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		ExpiresAt: expiresAt.Format(time.RFC3339),
	}
	return p.Publish(ctx, models.TokenCreated, event)
}

// PublishTokenRefreshed публикует событие обновления токена
func (p *Publisher) PublishTokenRefreshed(ctx context.Context, oldTokenID, newTokenID, userID, ip, userAgent string, expiresAt time.Time) error {
	event := models.TokenRefreshedEvent{
		OldTokenID:  oldTokenID,
		NewTokenID:  newTokenID,
		UserID:      userID,
		IP:          ip,
		UserAgent:   userAgent,
		RefreshedAt: time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:   expiresAt.Format(time.RFC3339),
	}
	return p.Publish(ctx, models.TokenRefreshed, event)
}

// PublishTokenRevoked публикует событие отзыва токена
func (p *Publisher) PublishTokenRevoked(ctx context.Context, tokenID, userID, revokedBy, reason string) error {
	event := models.TokenRevokedEvent{
		TokenID:   tokenID,
		UserID:    userID,
		RevokedBy: revokedBy,
		Reason:    reason,
		RevokedAt: time.Now().UTC().Format(time.RFC3339),
	}
	return p.Publish(ctx, models.TokenRevoked, event)
}

// PublishSecurityAlert публикует событие оповещения о безопасности
func (p *Publisher) PublishSecurityAlert(ctx context.Context, alertType, userID, ip, userAgent, severity, message string, details map[string]interface{}) error {
	event := models.SecurityAlertEvent{
		AlertType:  alertType,
		UserID:     userID,
		IP:         ip,
		UserAgent:  userAgent,
		Severity:   severity,
		Message:    message,
		Details:    details,
		DetectedAt: time.Now().UTC().Format(time.RFC3339),
	}
	return p.Publish(ctx, models.SecurityAlert, event)
}

// getTopicForEventType возвращает топик Kafka для указанного типа события
func (p *Publisher) getTopicForEventType(eventType models.EventType) string {
	// Определяем базовый топик
	baseTopic := p.config.TopicPrefix

	// Определяем суффикс топика в зависимости от типа события
	var suffix string
	switch {
	case strings.HasPrefix(string(eventType), "user."):
		suffix = "users"
	case strings.HasPrefix(string(eventType), "session."):
		suffix = "sessions"
	case strings.HasPrefix(string(eventType), "token."):
		suffix = "tokens"
	case strings.HasPrefix(string(eventType), "role."):
		suffix = "roles"
	case strings.HasPrefix(string(eventType), "permission."):
		suffix = "permissions"
	case strings.HasPrefix(string(eventType), "security."):
		suffix = "security"
	default:
		suffix = "events"
	}

	// Формируем полный топик
	return fmt.Sprintf("%s.%s", baseTopic, suffix)
}
