// account-service/internal/infrastructure/client/notification/notification_client.go
package notification

import (
"context"
"fmt"
"time"

"github.com/google/uuid"
"google.golang.org/grpc"
"google.golang.org/grpc/credentials/insecure"

pb "github.com/steamru/account-service/api/proto/notification"
)

// NotificationServiceClientImpl реализация клиента для Notification Service
type NotificationServiceClientImpl struct {
client pb.NotificationServiceClient
conn   *grpc.ClientConn
}

// NewNotificationServiceClient создает новый экземпляр клиента Notification Service
func NewNotificationServiceClient(address string) (*NotificationServiceClientImpl, error) {
conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
if err != nil {
return nil, fmt.Errorf("failed to connect to notification service: %w", err)
}

client := pb.NewNotificationServiceClient(conn)
return &NotificationServiceClientImpl{
client: client,
conn:   conn,
}, nil
}

// Close закрывает соединение с Notification Service
func (c *NotificationServiceClientImpl) Close() error {
if c.conn != nil {
return c.conn.Close()
}
return nil
}

// SendEmailVerificationNotification отправляет уведомление с кодом верификации email
func (c *NotificationServiceClientImpl) SendEmailVerificationNotification(ctx context.Context, accountID uuid.UUID, code string) error {
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()

_, err := c.client.SendEmailVerification(ctx, &pb.SendEmailVerificationRequest{
AccountId: accountID.String(),
Code:      code,
})
if err != nil {
return fmt.Errorf("failed to send email verification notification: %w", err)
}

return nil
}

// SendPasswordResetNotification отправляет уведомление со ссылкой для сброса пароля
func (c *NotificationServiceClientImpl) SendPasswordResetNotification(ctx context.Context, accountID uuid.UUID, token string) error {
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()

_, err := c.client.SendPasswordReset(ctx, &pb.SendPasswordResetRequest{
AccountId: accountID.String(),
Token:     token,
})
if err != nil {
return fmt.Errorf("failed to send password reset notification: %w", err)
}

return nil
}

// SendPasswordResetCompletedNotification отправляет уведомление о завершении сброса пароля
func (c *NotificationServiceClientImpl) SendPasswordResetCompletedNotification(ctx context.Context, accountID uuid.UUID) error {
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()

_, err := c.client.SendPasswordResetCompleted(ctx, &pb.SendPasswordResetCompletedRequest{
AccountId: accountID.String(),
})
if err != nil {
return fmt.Errorf("failed to send password reset completed notification: %w", err)
}

return nil
}

// SendPasswordChangedNotification отправляет уведомление об изменении пароля
func (c *NotificationServiceClientImpl) SendPasswordChangedNotification(ctx context.Context, accountID uuid.UUID) error {
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()

_, err := c.client.SendPasswordChanged(ctx, &pb.SendPasswordChangedRequest{
AccountId: accountID.String(),
})
if err != nil {
return fmt.Errorf("failed to send password changed notification: %w", err)
}

return nil
}

// SendAccountSuspendedNotification отправляет уведомление о приостановке аккаунта
func (c *NotificationServiceClientImpl) SendAccountSuspendedNotification(ctx context.Context, accountID uuid.UUID, reason string) error {
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()

_, err := c.client.SendAccountSuspended(ctx, &pb.SendAccountSuspendedRequest{
AccountId: accountID.String(),
Reason:    reason,
})
if err != nil {
return fmt.Errorf("failed to send account suspended notification: %w", err)
}

return nil
}

// SendAccountBannedNotification отправляет уведомление о блокировке аккаунта
func (c *NotificationServiceClientImpl) SendAccountBannedNotification(ctx context.Context, accountID uuid.UUID, reason string, until *time.Time) error {
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()

var untilTimestamp int64
if until != nil {
untilTimestamp = until.Unix()
}

_, err := c.client.SendAccountBanned(ctx, &pb.SendAccountBannedRequest{
AccountId: accountID.String(),
Reason:    reason,
Until:     untilTimestamp,
})
if err != nil {
return fmt.Errorf("failed to send account banned notification: %w", err)
}

return nil
}

// SendAccountDeletedNotification отправляет уведомление об удалении аккаунта
func (c *NotificationServiceClientImpl) SendAccountDeletedNotification(ctx context.Context, accountID uuid.UUID) error {
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()

_, err := c.client.SendAccountDeleted(ctx, &pb.SendAccountDeletedRequest{
AccountId: accountID.String(),
})
if err != nil {
return fmt.Errorf("failed to send account deleted notification: %w", err)
}

return nil
}
