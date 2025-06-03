// account-service\internal\infrastructure\kafka\consumer.go
package kafka

import (
	"context"
	"encoding/json"
	"time"

	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

// MessageHandler функция обработки сообщения
type MessageHandler func(ctx context.Context, key string, value []byte, headers map[string]string) error

// Consumer реализует интерфейс для получения событий из Kafka
type Consumer struct {
	reader  *kafka.Reader
	logger  *zap.SugaredLogger
	handler MessageHandler
}

// NewConsumer создает новый экземпляр Consumer
func NewConsumer(brokers []string, groupID, topic string, logger *zap.SugaredLogger, handler MessageHandler) *Consumer {
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		GroupID:        groupID,
		Topic:          topic,
		MinBytes:       10e3, // 10KB
		MaxBytes:       10e6, // 10MB
		CommitInterval: time.Second,
		StartOffset:    kafka.LastOffset,
	})

	return &Consumer{
		reader:  reader,
		logger:  logger,
		handler: handler,
	}
}

// Start запускает обработку сообщений
func (c *Consumer) Start(ctx context.Context) {
	go func() {
		c.logger.Info("Starting Kafka consumer")
		for {
			select {
			case <-ctx.Done():
				c.logger.Info("Stopping Kafka consumer")
				if err := c.reader.Close(); err != nil {
					c.logger.Errorw("Failed to close Kafka reader", "error", err)
				}
				return
			default:
				message, err := c.reader.ReadMessage(ctx)
				if err != nil {
					c.logger.Errorw("Failed to read message from Kafka", "error", err)
					continue
				}

				// Извлекаем заголовки
				headers := make(map[string]string)
				for _, header := range message.Headers {
					headers[header.Key] = string(header.Value)
				}

				// Обрабатываем сообщение
				if err := c.handler(ctx, string(message.Key), message.Value, headers); err != nil {
					c.logger.Errorw("Failed to handle message", "error", err, "key", string(message.Key))
					continue
				}

				c.logger.Infow("Message processed", "key", string(message.Key), "event_type", headers["event_type"])
			}
		}
	}()
}

// Close закрывает соединение с Kafka
func (c *Consumer) Close() error {
	return c.reader.Close()
}

// DefaultMessageHandler обработчик сообщений по умолчанию
func DefaultMessageHandler(logger *zap.SugaredLogger) MessageHandler {
	return func(ctx context.Context, key string, value []byte, headers map[string]string) error {
		// Логируем полученное сообщение
		eventType := headers["event_type"]
		logger.Infow("Received message", "key", key, "event_type", eventType)

		// Десериализуем данные из JSON
		var data map[string]interface{}
		if err := json.Unmarshal(value, &data); err != nil {
			logger.Errorw("Failed to unmarshal message value", "error", err)
			return err
		}

		// Обрабатываем сообщение в зависимости от типа события
		switch eventType {
		case "account.created":
			logger.Infow("Account created", "account_id", key, "data", data)
		case "account.updated":
			logger.Infow("Account updated", "account_id", key, "data", data)
		case "account.deleted":
			logger.Infow("Account deleted", "account_id", key)
		case "profile.created":
			logger.Infow("Profile created", "account_id", key, "data", data)
		case "profile.updated":
			logger.Infow("Profile updated", "account_id", key, "data", data)
		case "contact_info.created":
			logger.Infow("Contact info created", "account_id", key, "data", data)
		case "contact_info.updated":
			logger.Infow("Contact info updated", "account_id", key, "data", data)
		case "contact_info.deleted":
			logger.Infow("Contact info deleted", "id", key)
		case "verification.requested":
			logger.Infow("Verification requested", "account_id", key)
		case "setting.updated":
			logger.Infow("Setting updated", "account_id", key, "category", data["category"])
		default:
			logger.Warnw("Unknown event type", "event_type", eventType)
		}

		return nil
	}
}
