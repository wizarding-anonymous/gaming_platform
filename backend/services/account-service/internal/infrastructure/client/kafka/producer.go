// File: backend/services/account-service/internal/infrastructure/client/kafka/producer.go
// account-service/internal/infrastructure/kafka/producer.go
package kafka

import (
"context"
"encoding/json"
"fmt"
"time"

"github.com/google/uuid"
"github.com/segmentio/kafka-go"

"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/entity"
)

// CloudEvent представляет собой структуру события в формате CloudEvents
type CloudEvent struct {
ID              string      `json:"id"`
Source          string      `json:"source"`
Type            string      `json:"type"`
Time            time.Time   `json:"time"`
DataContentType string      `json:"datacontenttype"`
Data            interface{} `json:"data"`
}

// EventPublisherImpl реализация интерфейса для публикации событий
type EventPublisherImpl struct {
writer        *kafka.Writer
serviceName   string
accountTopic  string
profileTopic  string
contactTopic  string
settingsTopic string
}

// NewEventPublisher создает новый экземпляр издателя событий
func NewEventPublisher(brokers []string, serviceName, accountTopic, profileTopic, contactTopic, settingsTopic string) *EventPublisherImpl {
writer := &kafka.Writer{
Addr:         kafka.TCP(brokers...),
Balancer:     &kafka.LeastBytes{},
RequiredAcks: kafka.RequireOne,
Async:        false,
}

return &EventPublisherImpl{
writer:        writer,
serviceName:   serviceName,
accountTopic:  accountTopic,
profileTopic:  profileTopic,
contactTopic:  contactTopic,
settingsTopic: settingsTopic,
}
}

// Close закрывает соединение с Kafka
func (p *EventPublisherImpl) Close() error {
return p.writer.Close()
}

// createCloudEvent создает событие в формате CloudEvents
func (p *EventPublisherImpl) createCloudEvent(eventType string, data interface{}) CloudEvent {
return CloudEvent{
ID:              uuid.New().String(),
Source:          p.serviceName,
Type:            eventType,
Time:            time.Now().UTC(),
DataContentType: "application/json",
Data:            data,
}
}

// publishEvent публикует событие в Kafka
func (p *EventPublisherImpl) publishEvent(ctx context.Context, topic string, eventType string, data interface{}) error {
event := p.createCloudEvent(eventType, data)

eventJSON, err := json.Marshal(event)
if err != nil {
return fmt.Errorf("failed to marshal event: %w", err)
}

err = p.writer.WriteMessages(ctx, kafka.Message{
Topic: topic,
Key:   []byte(event.ID),
Value: eventJSON,
})
if err != nil {
return fmt.Errorf("failed to publish event: %w", err)
}

return nil
}

// PublishAccountCreated публикует событие о создании аккаунта
func (p *EventPublisherImpl) PublishAccountCreated(ctx context.Context, account *entity.Account) error {
return p.publishEvent(ctx, p.accountTopic, "account.created", account)
}

// PublishAccountUpdated публикует событие об обновлении аккаунта
func (p *EventPublisherImpl) PublishAccountUpdated(ctx context.Context, account *entity.Account) error {
return p.publishEvent(ctx, p.accountTopic, "account.updated", account)
}

// PublishAccountDeleted публикует событие об удалении аккаунта
func (p *EventPublisherImpl) PublishAccountDeleted(ctx context.Context, account *entity.Account) error {
return p.publishEvent(ctx, p.accountTopic, "account.deleted", account)
}

// PublishAccountStatusChanged публикует событие об изменении статуса аккаунта
func (p *EventPublisherImpl) PublishAccountStatusChanged(ctx context.Context, account *entity.Account) error {
return p.publishEvent(ctx, p.accountTopic, "account.status_changed", account)
}

// PublishAccountRoleChanged публикует событие об изменении роли аккаунта
func (p *EventPublisherImpl) PublishAccountRoleChanged(ctx context.Context, account *entity.Account) error {
return p.publishEvent(ctx, p.accountTopic, "account.role_changed", account)
}

// PublishAccountEmailChanged публикует событие об изменении email аккаунта
func (p *EventPublisherImpl) PublishAccountEmailChanged(ctx context.Context, account *entity.Account, oldEmail string) error {
data := map[string]interface{}{
"account":   account,
"old_email": oldEmail,
}
return p.publishEvent(ctx, p.accountTopic, "account.email_changed", data)
}

// PublishAccountUsernameChanged публикует событие об изменении username аккаунта
func (p *EventPublisherImpl) PublishAccountUsernameChanged(ctx context.Context, account *entity.Account, oldUsername string) error {
data := map[string]interface{}{
"account":      account,
"old_username": oldUsername,
}
return p.publishEvent(ctx, p.accountTopic, "account.username_changed", data)
}

// PublishAccountPasswordChanged публикует событие об изменении пароля аккаунта
func (p *EventPublisherImpl) PublishAccountPasswordChanged(ctx context.Context, account *entity.Account) error {
return p.publishEvent(ctx, p.accountTopic, "account.password_changed", account)
}

// PublishAccountPasswordReset публикует событие о сбросе пароля аккаунта
func (p *EventPublisherImpl) PublishAccountPasswordReset(ctx context.Context, account *entity.Account) error {
return p.publishEvent(ctx, p.accountTopic, "account.password_reset", account)
}

// PublishAccountPasswordResetRequested публикует событие о запросе сброса пароля аккаунта
func (p *EventPublisherImpl) PublishAccountPasswordResetRequested(ctx context.Context, account *entity.Account) error {
return p.publishEvent(ctx, p.accountTopic, "account.password_reset_requested", account)
}

// PublishAccountEmailVerified публикует событие о верификации email аккаунта
func (p *EventPublisherImpl) PublishAccountEmailVerified(ctx context.Context, account *entity.Account) error {
return p.publishEvent(ctx, p.accountTopic, "account.email_verified", account)
}

// PublishProfileCreated публикует событие о создании профиля
func (p *EventPublisherImpl) PublishProfileCreated(ctx context.Context, profile *entity.Profile) error {
return p.publishEvent(ctx, p.profileTopic, "profile.created", profile)
}

// PublishProfileUpdated публикует событие об обновлении профиля
func (p *EventPublisherImpl) PublishProfileUpdated(ctx context.Context, profile *entity.Profile) error {
return p.publishEvent(ctx, p.profileTopic, "profile.updated", profile)
}

// PublishContactInfoCreated публикует событие о создании контактной информации
func (p *EventPublisherImpl) PublishContactInfoCreated(ctx context.Context, contactInfo *entity.ContactInfo) error {
return p.publishEvent(ctx, p.contactTopic, "contact_info.created", contactInfo)
}

// PublishContactInfoUpdated публикует событие об обновлении контактной информации
func (p *EventPublisherImpl) PublishContactInfoUpdated(ctx context.Context, contactInfo *entity.ContactInfo) error {
return p.publishEvent(ctx, p.contactTopic, "contact_info.updated", contactInfo)
}

// PublishContactInfoDeleted публикует событие об удалении контактной информации
func (p *EventPublisherImpl) PublishContactInfoDeleted(ctx context.Context, contactInfo *entity.ContactInfo) error {
return p.publishEvent(ctx, p.contactTopic, "contact_info.deleted", contactInfo)
}

// PublishContactInfoVerified публикует событие о верификации контактной информации
func (p *EventPublisherImpl) PublishContactInfoVerified(ctx context.Context, contactInfo *entity.ContactInfo) error {
return p.publishEvent(ctx, p.contactTopic, "contact_info.verified", contactInfo)
}

// PublishSettingsUpdated публикует событие об обновлении настроек
func (p *EventPublisherImpl) PublishSettingsUpdated(ctx context.Context, setting *entity.Setting) error {
return p.publishEvent(ctx, p.settingsTopic, "settings.updated", setting)
}
