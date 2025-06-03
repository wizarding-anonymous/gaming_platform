// File: internal/events/kafka/consumer.go

package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/Shopify/sarama"
	"github.com/your-org/auth-service/internal/utils/logger"
)

// Consumer представляет собой потребителя Kafka для получения событий
type Consumer struct {
	consumer sarama.ConsumerGroup
	topics   []string
	logger   logger.Logger
	handlers map[string]EventHandler
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// EventHandler представляет собой обработчик событий
type EventHandler func(ctx context.Context, event EventMessage) error

// NewConsumer создает новый экземпляр потребителя Kafka
func NewConsumer(brokers []string, groupID string, topics []string, logger logger.Logger) (*Consumer, error) {
	config := sarama.NewConfig()
	config.Consumer.Group.Rebalance.Strategy = sarama.BalanceStrategyRoundRobin
	config.Consumer.Offsets.Initial = sarama.OffsetNewest
	config.Consumer.Return.Errors = true

	// Создаем потребителя
	consumer, err := sarama.NewConsumerGroup(brokers, groupID, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kafka consumer: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Consumer{
		consumer: consumer,
		topics:   topics,
		logger:   logger,
		handlers: make(map[string]EventHandler),
		ctx:      ctx,
		cancel:   cancel,
	}, nil
}

// RegisterHandler регистрирует обработчик для определенного типа события
func (c *Consumer) RegisterHandler(eventType string, handler EventHandler) {
	c.handlers[eventType] = handler
}

// Start запускает потребителя Kafka
func (c *Consumer) Start() error {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for {
			// Проверяем, был ли контекст отменен
			if c.ctx.Err() != nil {
				return
			}

			// Создаем обработчик для группы потребителей
			handler := &consumerGroupHandler{
				logger:   c.logger,
				handlers: c.handlers,
			}

			// Запускаем потребителя
			err := c.consumer.Consume(c.ctx, c.topics, handler)
			if err != nil {
				c.logger.Error("Error from consumer", "error", err)
			}

			// Проверяем, был ли контекст отменен
			if c.ctx.Err() != nil {
				return
			}
		}
	}()

	// Настраиваем обработку сигналов для корректного завершения
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signals
		c.Stop()
	}()

	return nil
}

// Stop останавливает потребителя Kafka
func (c *Consumer) Stop() {
	c.cancel()
	c.wg.Wait()
	if err := c.consumer.Close(); err != nil {
		c.logger.Error("Error closing consumer", "error", err)
	}
}

// consumerGroupHandler реализует интерфейс sarama.ConsumerGroupHandler
type consumerGroupHandler struct {
	logger   logger.Logger
	handlers map[string]EventHandler
}

// Setup вызывается при настройке сессии потребителя
func (h *consumerGroupHandler) Setup(session sarama.ConsumerGroupSession) error {
	h.logger.Info("Consumer group session setup", "member_id", session.MemberID())
	return nil
}

// Cleanup вызывается при завершении сессии потребителя
func (h *consumerGroupHandler) Cleanup(session sarama.ConsumerGroupSession) error {
	h.logger.Info("Consumer group session cleanup", "member_id", session.MemberID())
	return nil
}

// ConsumeClaim обрабатывает сообщения из партиции
func (h *consumerGroupHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for message := range claim.Messages() {
		h.logger.Debug("Received message",
			"topic", message.Topic,
			"partition", message.Partition,
			"offset", message.Offset,
			"key", string(message.Key),
		)

		// Десериализуем сообщение
		var event EventMessage
		if err := json.Unmarshal(message.Value, &event); err != nil {
			h.logger.Error("Failed to unmarshal event", "error", err)
			session.MarkMessage(message, "")
			continue
		}

		// Находим обработчик для типа события
		handler, ok := h.handlers[event.EventType]
		if !ok {
			h.logger.Warn("No handler registered for event type", "event_type", event.EventType)
			session.MarkMessage(message, "")
			continue
		}

		// Создаем контекст с метаданными
		ctx := context.Background()
		if event.Metadata.TraceID != "" {
			ctx = context.WithValue(ctx, "trace_id", event.Metadata.TraceID)
		}
		if event.Metadata.UserID != "" {
			ctx = context.WithValue(ctx, "user_id", event.Metadata.UserID)
		}

		// Обрабатываем событие
		if err := handler(ctx, event); err != nil {
			h.logger.Error("Failed to handle event",
				"error", err,
				"event_type", event.EventType,
				"user_id", event.Metadata.UserID,
				"trace_id", event.Metadata.TraceID,
			)
		} else {
			h.logger.Info("Event processed successfully",
				"event_type", event.EventType,
				"user_id", event.Metadata.UserID,
				"trace_id", event.Metadata.TraceID,
			)
		}

		// Отмечаем сообщение как обработанное
		session.MarkMessage(message, "")
	}
	return nil
}
