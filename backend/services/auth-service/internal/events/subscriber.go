// File: internal/events/subscriber/subscriber.go

package subscriber

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/events/kafka"
	"github.com/your-org/auth-service/internal/events/models"
	"github.com/your-org/auth-service/internal/utils/logger"
)

// EventHandler представляет обработчик событий
type EventHandler func(ctx context.Context, event *models.Event) error

// Subscriber представляет подписчика на события
type Subscriber struct {
	consumer     kafka.Consumer
	logger       logger.Logger
	config       *config.EventConfig
	handlers     map[models.EventType][]EventHandler
	mu           sync.RWMutex
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

// NewSubscriber создает новый экземпляр подписчика на события
func NewSubscriber(consumer kafka.Consumer, logger logger.Logger, config *config.EventConfig) *Subscriber {
	return &Subscriber{
		consumer: consumer,
		logger:   logger,
		config:   config,
		handlers: make(map[models.EventType][]EventHandler),
		stopCh:   make(chan struct{}),
	}
}

// Subscribe подписывается на события указанного типа
func (s *Subscriber) Subscribe(eventType models.EventType, handler EventHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.handlers[eventType] = append(s.handlers[eventType], handler)
	s.logger.Info("Subscribed to event", "event_type", eventType)
}

// Start запускает подписчика
func (s *Subscriber) Start(ctx context.Context) error {
	// Если события отключены, ничего не делаем
	if !s.config.Enabled {
		s.logger.Info("Events are disabled, subscriber not started")
		return nil
	}

	// Определяем топики для подписки
	topics := s.getTopics()
	if len(topics) == 0 {
		s.logger.Warn("No topics to subscribe to")
		return nil
	}

	// Подписываемся на топики
	err := s.consumer.Subscribe(topics)
	if err != nil {
		s.logger.Error("Failed to subscribe to topics", "error", err, "topics", topics)
		return fmt.Errorf("failed to subscribe to topics: %w", err)
	}

	s.logger.Info("Subscribed to topics", "topics", topics)

	// Запускаем обработку сообщений
	s.wg.Add(1)
	go s.consumeMessages(ctx)

	return nil
}

// Stop останавливает подписчика
func (s *Subscriber) Stop() {
	close(s.stopCh)
	s.wg.Wait()
	s.logger.Info("Subscriber stopped")
}

// consumeMessages обрабатывает сообщения из Kafka
func (s *Subscriber) consumeMessages(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("Context canceled, stopping subscriber")
			return
		case <-s.stopCh:
			s.logger.Info("Stop signal received, stopping subscriber")
			return
		default:
			// Получаем сообщение из Kafka
			msg, err := s.consumer.Consume(ctx, 100) // Таймаут 100 мс
			if err != nil {
				s.logger.Error("Failed to consume message", "error", err)
				continue
			}

			// Если сообщение пустое (таймаут), продолжаем
			if msg == nil {
				continue
			}

			// Обрабатываем сообщение
			s.handleMessage(ctx, msg)
		}
	}
}

// handleMessage обрабатывает сообщение из Kafka
func (s *Subscriber) handleMessage(ctx context.Context, msg *kafka.Message) {
	// Десериализуем сообщение в событие
	var event models.Event
	err := json.Unmarshal(msg.Value, &event)
	if err != nil {
		s.logger.Error("Failed to unmarshal event", "error", err, "topic", msg.Topic, "key", msg.Key)
		// Подтверждаем сообщение, чтобы не обрабатывать его повторно
		if err := s.consumer.Commit(msg); err != nil {
			s.logger.Error("Failed to commit message", "error", err, "topic", msg.Topic, "key", msg.Key)
		}
		return
	}

	s.logger.Info("Received event", "event_id", event.ID, "event_type", event.Type, "topic", msg.Topic)

	// Получаем обработчики для данного типа события
	s.mu.RLock()
	handlers := s.handlers[event.Type]
	s.mu.RUnlock()

	// Если обработчиков нет, подтверждаем сообщение и выходим
	if len(handlers) == 0 {
		s.logger.Debug("No handlers for event", "event_type", event.Type)
		if err := s.consumer.Commit(msg); err != nil {
			s.logger.Error("Failed to commit message", "error", err, "topic", msg.Topic, "key", msg.Key)
		}
		return
	}

	// Вызываем все обработчики
	for _, handler := range handlers {
		err := handler(ctx, &event)
		if err != nil {
			s.logger.Error("Failed to handle event", "error", err, "event_id", event.ID, "event_type", event.Type)
			// Не подтверждаем сообщение, чтобы обработать его повторно
			return
		}
	}

	// Подтверждаем сообщение
	if err := s.consumer.Commit(msg); err != nil {
		s.logger.Error("Failed to commit message", "error", err, "topic", msg.Topic, "key", msg.Key)
	}
}

// getTopics возвращает список топиков для подписки
func (s *Subscriber) getTopics() []string {
	// Определяем базовый топик
	baseTopic := s.config.TopicPrefix

	// Определяем суффиксы топиков
	suffixes := []string{
		"users",
		"sessions",
		"tokens",
		"roles",
		"permissions",
		"security",
		"events",
	}

	// Формируем полные топики
	topics := make([]string, len(suffixes))
	for i, suffix := range suffixes {
		topics[i] = fmt.Sprintf("%s.%s", baseTopic, suffix)
	}

	return topics
}
