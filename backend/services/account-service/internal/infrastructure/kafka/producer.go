// File: backend/services/account-service/internal/infrastructure/kafka/producer.go
// account-service/internal/infrastructure/kafka/producer.go

package kafka

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/utils/logger"
)

// CloudEvent представляет структуру события в формате CloudEvents
type CloudEvent struct {
	// Обязательные атрибуты CloudEvents
	ID          string    `json:"id"`
	Source      string    `json:"source"`
	SpecVersion string    `json:"specversion"`
	Type        string    `json:"type"`
	Time        time.Time `json:"time"`

	// Опциональные атрибуты CloudEvents
	Subject     string `json:"subject,omitempty"`
	DataSchema  string `json:"dataschema,omitempty"`
	ContentType string `json:"contenttype"`

	// Данные события
	Data json.RawMessage `json:"data"`
}

// EventProducer интерфейс для публикации событий
type EventProducer interface {
	PublishEvent(ctx context.Context, eventType string, subject string, data interface{}) error
	Close() error
}

// KafkaEventProducer реализация EventProducer для Kafka
type KafkaEventProducer struct {
	writer     *kafka.Writer
	sourceName string
}

// NewKafkaEventProducer создает новый экземпляр KafkaEventProducer
func NewKafkaEventProducer(brokers []string, sourceName string) *KafkaEventProducer {
	writer := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Balancer:     &kafka.LeastBytes{},
		RequiredAcks: kafka.RequireAll,
		Async:        false,
	}

	return &KafkaEventProducer{
		writer:     writer,
		sourceName: sourceName,
	}
}

// PublishEvent публикует событие в Kafka в формате CloudEvents
func (p *KafkaEventProducer) PublishEvent(ctx context.Context, eventType string, subject string, data interface{}) error {
	// Определяем топик на основе типа события
	topic := getTopicFromEventType(eventType)
	p.writer.Topic = topic

	// Сериализуем данные события
	dataBytes, err := json.Marshal(data)
	if err != nil {
		logger.Error("Ошибка сериализации данных события", "error", err)
		return err
	}

	// Создаем CloudEvent
	event := CloudEvent{
		ID:          uuid.New().String(),
		Source:      p.sourceName,
		SpecVersion: "1.0",
		Type:        eventType,
		Time:        time.Now().UTC(),
		Subject:     subject,
		ContentType: "application/json",
		Data:        dataBytes,
	}

	// Сериализуем CloudEvent
	eventBytes, err := json.Marshal(event)
	if err != nil {
		logger.Error("Ошибка сериализации CloudEvent", "error", err)
		return err
	}

	// Публикуем сообщение в Kafka
	err = p.writer.WriteMessages(ctx, kafka.Message{
		Key:   []byte(subject),
		Value: eventBytes,
		Headers: []kafka.Header{
			{Key: "ce_id", Value: []byte(event.ID)},
			{Key: "ce_source", Value: []byte(event.Source)},
			{Key: "ce_specversion", Value: []byte(event.SpecVersion)},
			{Key: "ce_type", Value: []byte(event.Type)},
			{Key: "ce_time", Value: []byte(event.Time.Format(time.RFC3339))},
			{Key: "ce_subject", Value: []byte(event.Subject)},
			{Key: "ce_contenttype", Value: []byte(event.ContentType)},
		},
	})

	if err != nil {
		logger.Error("Ошибка публикации события в Kafka", "error", err, "topic", topic, "event_type", eventType)
		return err
	}

	logger.Info("Событие опубликовано в Kafka", "topic", topic, "event_type", eventType, "subject", subject)
	return nil
}

// Close закрывает соединение с Kafka
func (p *KafkaEventProducer) Close() error {
	return p.writer.Close()
}

// getTopicFromEventType определяет топик Kafka на основе типа события
func getTopicFromEventType(eventType string) string {
	switch {
	case eventType == "account.created" || eventType == "account.updated" || eventType == "account.deleted" || eventType == "account.blocked" || eventType == "account.activated":
		return "accounts"
	case eventType == "profile.created" || eventType == "profile.updated":
		return "profiles"
	case eventType == "contact.verified" || eventType == "contact.added" || eventType == "contact.updated" || eventType == "contact.deleted":
		return "contacts"
	case eventType == "avatar.uploaded" || eventType == "avatar.deleted" || eventType == "avatar.set_current":
		return "avatars"
	case eventType == "settings.updated":
		return "settings"
	default:
		return "account-service-events"
	}
}

// Singleton instance
var producer EventProducer

// InitProducer инициализирует глобальный экземпляр EventProducer
func InitProducer(brokers []string, sourceName string) {
	producer = NewKafkaEventProducer(brokers, sourceName)
}

// GetProducer возвращает глобальный экземпляр EventProducer
func GetProducer() EventProducer {
	if producer == nil {
		panic("EventProducer не инициализирован. Вызовите InitProducer перед использованием.")
	}
	return producer
}

// PublishAccountCreated публикует событие о создании аккаунта
func PublishAccountCreated(ctx context.Context, accountID uuid.UUID, username string) error {
	data := map[string]interface{}{
		"account_id": accountID.String(),
		"username":   username,
		"timestamp":  time.Now().UTC(),
	}
	return GetProducer().PublishEvent(ctx, "account.created", accountID.String(), data)
}

// PublishAccountUpdated публикует событие об обновлении аккаунта
func PublishAccountUpdated(ctx context.Context, accountID uuid.UUID, username string) error {
	data := map[string]interface{}{
		"account_id": accountID.String(),
		"username":   username,
		"timestamp":  time.Now().UTC(),
	}
	return GetProducer().PublishEvent(ctx, "account.updated", accountID.String(), data)
}

// PublishAccountDeleted публикует событие об удалении аккаунта
func PublishAccountDeleted(ctx context.Context, accountID uuid.UUID) error {
	data := map[string]interface{}{
		"account_id": accountID.String(),
		"timestamp":  time.Now().UTC(),
	}
	return GetProducer().PublishEvent(ctx, "account.deleted", accountID.String(), data)
}

// PublishAccountBlocked публикует событие о блокировке аккаунта
func PublishAccountBlocked(ctx context.Context, accountID uuid.UUID, reason string) error {
	data := map[string]interface{}{
		"account_id": accountID.String(),
		"reason":     reason,
		"timestamp":  time.Now().UTC(),
	}
	return GetProducer().PublishEvent(ctx, "account.blocked", accountID.String(), data)
}

// PublishAccountActivated публикует событие об активации аккаунта
func PublishAccountActivated(ctx context.Context, accountID uuid.UUID) error {
	data := map[string]interface{}{
		"account_id": accountID.String(),
		"timestamp":  time.Now().UTC(),
	}
	return GetProducer().PublishEvent(ctx, "account.activated", accountID.String(), data)
}

// PublishProfileUpdated публикует событие об обновлении профиля
func PublishProfileUpdated(ctx context.Context, accountID uuid.UUID, nickname string) error {
	data := map[string]interface{}{
		"account_id": accountID.String(),
		"nickname":   nickname,
		"timestamp":  time.Now().UTC(),
	}
	return GetProducer().PublishEvent(ctx, "profile.updated", accountID.String(), data)
}

// PublishContactVerified публикует событие о верификации контактной информации
func PublishContactVerified(ctx context.Context, accountID uuid.UUID, contactType string, value string) error {
	data := map[string]interface{}{
		"account_id": accountID.String(),
		"type":       contactType,
		"value":      value,
		"timestamp":  time.Now().UTC(),
	}
	return GetProducer().PublishEvent(ctx, "contact.verified", accountID.String(), data)
}

// PublishAvatarUploaded публикует событие о загрузке аватара
func PublishAvatarUploaded(ctx context.Context, accountID uuid.UUID, avatarID uuid.UUID, url string) error {
	data := map[string]interface{}{
		"account_id": accountID.String(),
		"avatar_id":  avatarID.String(),
		"url":        url,
		"timestamp":  time.Now().UTC(),
	}
	return GetProducer().PublishEvent(ctx, "avatar.uploaded", accountID.String(), data)
}

// PublishSettingsUpdated публикует событие об обновлении настроек
func PublishSettingsUpdated(ctx context.Context, accountID uuid.UUID, category string) error {
	data := map[string]interface{}{
		"account_id": accountID.String(),
		"category":   category,
		"timestamp":  time.Now().UTC(),
	}
	return GetProducer().PublishEvent(ctx, "settings.updated", accountID.String(), data)
}
