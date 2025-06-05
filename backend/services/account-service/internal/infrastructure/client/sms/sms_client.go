// File: backend/services/account-service/internal/infrastructure/client/sms/sms_client.go
// account-service/internal/infrastructure/client/sms/sms_client.go
package sms

import (
"context"
"fmt"
"net/http"
"net/url"
"strings"
"time"
)

// SMSClientImpl реализация клиента для отправки SMS
type SMSClientImpl struct {
httpClient *http.Client
apiURL     string
apiKey     string
sender     string
}

// NewSMSClient создает новый экземпляр клиента для отправки SMS
func NewSMSClient(apiURL, apiKey, sender string, timeout time.Duration) *SMSClientImpl {
return &SMSClientImpl{
httpClient: &http.Client{
Timeout: timeout,
},
apiURL: apiURL,
apiKey: apiKey,
sender: sender,
}
}

// SendVerificationCode отправляет SMS с кодом верификации
func (c *SMSClientImpl) SendVerificationCode(ctx context.Context, phone string, code string) error {
message := fmt.Sprintf("Ваш код подтверждения: %s", code)
return c.sendSMS(ctx, phone, message)
}

// SendPasswordResetCode отправляет SMS с кодом для сброса пароля
func (c *SMSClientImpl) SendPasswordResetCode(ctx context.Context, phone string, code string) error {
message := fmt.Sprintf("Код для сброса пароля: %s", code)
return c.sendSMS(ctx, phone, message)
}

// SendNotification отправляет SMS с уведомлением
func (c *SMSClientImpl) SendNotification(ctx context.Context, phone string, message string) error {
return c.sendSMS(ctx, phone, message)
}

// sendSMS отправляет SMS через API провайдера
func (c *SMSClientImpl) sendSMS(ctx context.Context, phone string, message string) error {
// Формирование запроса
data := url.Values{}
data.Set("api_key", c.apiKey)
data.Set("to", phone)
data.Set("from", c.sender)
data.Set("message", message)

// Создание HTTP запроса
req, err := http.NewRequestWithContext(
ctx,
http.MethodPost,
c.apiURL,
strings.NewReader(data.Encode()),
)
if err != nil {
return fmt.Errorf("failed to create request: %w", err)
}

// Установка заголовков
req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

// Выполнение запроса
resp, err := c.httpClient.Do(req)
if err != nil {
return fmt.Errorf("failed to send SMS: %w", err)
}
defer resp.Body.Close()

// Проверка статуса ответа
if resp.StatusCode != http.StatusOK {
return fmt.Errorf("SMS provider returned non-OK status: %d", resp.StatusCode)
}

return nil
}
