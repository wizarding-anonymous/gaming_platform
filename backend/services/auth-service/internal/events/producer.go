// File: internal/events/kafka/producer.go

package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Shopify/sarama"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/logger"
)

// Producer представляет собой продюсер Kafka для отправки событий
type Producer struct {
	producer sarama.SyncProducer
	logger   logger.Logger
}

// NewProducer создает новый экземпляр продюсера Kafka
func NewProducer(brokers []string, logger logger.Logger) (*Producer, error) {
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 5
	config.Producer.Return.Successes = true
	config.Producer.Compression = sarama.CompressionSnappy
	config.Producer.Flush.Frequency = 500 * time.Millisecond
	config.Producer.Idempotent = true
	config.Net.MaxOpenRequests = 1

	// Создаем продюсера
	producer, err := sarama.NewSyncProducer(brokers, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kafka producer: %w", err)
	}

	return &Producer{
		producer: producer,
		logger:   logger,
	}, nil
}

// EventMessage представляет собой сообщение события
type EventMessage struct {
	EventType string      `json:"event_type"`
	Payload   interface{} `json:"payload"`
	Metadata  Metadata    `json:"metadata"`
}

// Metadata содержит метаданные события
type Metadata struct {
	UserID    string    `json:"user_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	TraceID   string    `json:"trace_id,omitempty"`
	Version   string    `json:"version"`
	Source    string    `json:"source"`
}

// SendEvent отправляет событие в указанный топик Kafka
func (p *Producer) SendEvent(ctx context.Context, topic string, eventType string, payload interface{}, metadata Metadata) error {
	// Устанавливаем время события, если оно не установлено
	if metadata.Timestamp.IsZero() {
		metadata.Timestamp = time.Now().UTC()
	}

	// Устанавливаем источник события, если он не установлен
	if metadata.Source == "" {
		metadata.Source = "auth-service"
	}

	// Устанавливаем версию события, если она не установлена
	if metadata.Version == "" {
		metadata.Version = "1.0"
	}

	// Создаем сообщение события
	event := EventMessage{
		EventType: eventType,
		Payload:   payload,
		Metadata:  metadata,
	}

	// Сериализуем событие в JSON
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event to JSON: %w", err)
	}

	// Создаем сообщение Kafka
	msg := &sarama.ProducerMessage{
		Topic: topic,
		Value: sarama.ByteEncoder(eventJSON),
		Key:   sarama.StringEncoder(metadata.UserID), // Используем UserID как ключ для партиционирования
	}

	// Отправляем сообщение
	partition, offset, err := p.producer.SendMessage(msg)
	if err != nil {
		return fmt.Errorf("failed to send message to Kafka: %w", err)
	}

	p.logger.Info("Event sent to Kafka",
		"topic", topic,
		"event_type", eventType,
		"partition", partition,
		"offset", offset,
		"user_id", metadata.UserID,
		"trace_id", metadata.TraceID,
	)

	return nil
}

// SendUserEvent отправляет событие, связанное с пользователем
func (p *Producer) SendUserEvent(ctx context.Context, eventType string, userID string, payload interface{}, traceID string) error {
	metadata := Metadata{
		UserID:    userID,
		Timestamp: time.Now().UTC(),
		TraceID:   traceID,
		Version:   "1.0",
		Source:    "auth-service",
	}

	return p.SendEvent(ctx, "auth.users", eventType, payload, metadata)
}

// SendAuthEvent отправляет событие аутентификации
func (p *Producer) SendAuthEvent(ctx context.Context, eventType string, userID string, payload interface{}, traceID string) error {
	metadata := Metadata{
		UserID:    userID,
		Timestamp: time.Now().UTC(),
		TraceID:   traceID,
		Version:   "1.0",
		Source:    "auth-service",
	}

	return p.SendEvent(ctx, "auth.events", eventType, payload, metadata)
}

// Close закрывает продюсера Kafka
func (p *Producer) Close() error {
	if err := p.producer.Close(); err != nil {
		return fmt.Errorf("failed to close Kafka producer: %w", err)
	}
	return nil
}
