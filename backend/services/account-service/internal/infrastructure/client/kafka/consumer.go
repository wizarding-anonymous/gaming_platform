// File: backend/services/account-service/internal/infrastructure/client/kafka/consumer.go
// account-service/internal/infrastructure/kafka/consumer.go
package kafka

import (
"context"
"encoding/json"
"fmt"
"log"
"time"

"github.com/segmentio/kafka-go"
)

// EventHandler представляет собой обработчик событий
type EventHandler func(ctx context.Context, event CloudEvent) error

// EventConsumerImpl реализация интерфейса для потребления событий
type EventConsumerImpl struct {
reader   *kafka.Reader
handlers map[string]EventHandler
}

// NewEventConsumer создает новый экземпляр потребителя событий
func NewEventConsumer(brokers []string, groupID string, topic string) *EventConsumerImpl {
reader := kafka.NewReader(kafka.ReaderConfig{
Brokers:        brokers,
GroupID:        groupID,
Topic:          topic,
MinBytes:       10e3, // 10KB
MaxBytes:       10e6, // 10MB
CommitInterval: time.Second,
StartOffset:    kafka.LastOffset,
})

return &EventConsumerImpl{
reader:   reader,
handlers: make(map[string]EventHandler),
}
}

// Close закрывает соединение с Kafka
func (c *EventConsumerImpl) Close() error {
return c.reader.Close()
}

// RegisterHandler регистрирует обработчик для определенного типа событий
func (c *EventConsumerImpl) RegisterHandler(eventType string, handler EventHandler) {
c.handlers[eventType] = handler
}

// Start запускает потребление событий
func (c *EventConsumerImpl) Start(ctx context.Context) error {
for {
select {
case <-ctx.Done():
return ctx.Err()
default:
// Чтение сообщения из Kafka
msg, err := c.reader.ReadMessage(ctx)
if err != nil {
log.Printf("Error reading message: %v", err)
continue
}

// Десериализация события
var event CloudEvent
if err := json.Unmarshal(msg.Value, &event); err != nil {
log.Printf("Error unmarshaling event: %v", err)
continue
}

// Поиск обработчика для типа события
handler, ok := c.handlers[event.Type]
if !ok {
log.Printf("No handler registered for event type: %s", event.Type)
continue
}

// Обработка события
if err := handler(ctx, event); err != nil {
log.Printf("Error handling event: %v", err)
continue
}
}
}
}

// StartAsync запускает потребление событий в отдельной горутине
func (c *EventConsumerImpl) StartAsync(ctx context.Context) {
go func() {
if err := c.Start(ctx); err != nil && err != context.Canceled {
log.Printf("Event consumer stopped with error: %v", err)
}
}()
}

// ProcessAuthEvents обрабатывает события от сервиса Auth
func ProcessAuthEvents(ctx context.Context, event CloudEvent) error {
switch event.Type {
case "auth.user_registered":
// Обработка события о регистрации пользователя
return processUserRegistered(ctx, event)
case "auth.user_deleted":
// Обработка события об удалении пользователя
return processUserDeleted(ctx, event)
case "auth.role_changed":
// Обработка события об изменении роли пользователя
return processRoleChanged(ctx, event)
default:
return fmt.Errorf("unknown auth event type: %s", event.Type)
}
}

// processUserRegistered обрабатывает событие о регистрации пользователя
func processUserRegistered(ctx context.Context, event CloudEvent) error {
// Здесь должна быть логика обработки события
// Например, создание аккаунта на основе данных из Auth
return nil
}

// processUserDeleted обрабатывает событие об удалении пользователя
func processUserDeleted(ctx context.Context, event CloudEvent) error {
// Здесь должна быть логика обработки события
// Например, удаление аккаунта на основе данных из Auth
return nil
}

// processRoleChanged обрабатывает событие об изменении роли пользователя
func processRoleChanged(ctx context.Context, event CloudEvent) error {
// Здесь должна быть логика обработки события
// Например, обновление роли аккаунта на основе данных из Auth
return nil
}
