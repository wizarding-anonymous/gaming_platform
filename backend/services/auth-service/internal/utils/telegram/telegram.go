// File: internal/utils/telegram/telegram.go

package telegram

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/logger"
)

// Client представляет клиент для работы с Telegram API
type Client struct {
	config *config.TelegramConfig
	logger logger.Logger
	client *http.Client
}

// NewClient создает новый клиент Telegram
func NewClient(config *config.TelegramConfig, logger logger.Logger) *Client {
	return &Client{
		config: config,
		logger: logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// TelegramUser представляет данные пользователя Telegram
type TelegramUser struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name,omitempty"`
	Username  string `json:"username,omitempty"`
	PhotoURL  string `json:"photo_url,omitempty"`
	AuthDate  int64  `json:"auth_date"`
	Hash      string `json:"hash"`
}

// ValidateAuthData проверяет данные аутентификации Telegram
func (c *Client) ValidateAuthData(data map[string]string) (*TelegramUser, error) {
	// Проверяем наличие всех необходимых полей
	requiredFields := []string{"id", "first_name", "auth_date", "hash"}
	for _, field := range requiredFields {
		if _, ok := data[field]; !ok {
			return nil, fmt.Errorf("missing required field: %s", field)
		}
	}

	// Проверяем хеш
	hash := data["hash"]
	delete(data, "hash")

	// Сортируем поля по ключу
	var keys []string
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Создаем строку для проверки
	var dataCheckString strings.Builder
	for _, k := range keys {
		dataCheckString.WriteString(k)
		dataCheckString.WriteString("=")
		dataCheckString.WriteString(data[k])
		dataCheckString.WriteString("\n")
	}
	// Удаляем последний символ новой строки
	checkString := dataCheckString.String()
	if len(checkString) > 0 {
		checkString = checkString[:len(checkString)-1]
	}

	// Создаем секретный ключ
	secretKey := sha256.Sum256([]byte(c.config.BotToken))

	// Вычисляем HMAC-SHA-256
	h := hmac.New(sha256.New, secretKey[:])
	h.Write([]byte(checkString))
	calculatedHash := hex.EncodeToString(h.Sum(nil))

	// Сравниваем хеши
	if calculatedHash != hash {
		return nil, errors.New("invalid hash")
	}

	// Проверяем время аутентификации
	authDate, err := strconv.ParseInt(data["auth_date"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid auth_date: %w", err)
	}

	// Проверяем, что аутентификация не устарела (не более 24 часов)
	if time.Now().Unix()-authDate > 86400 {
		return nil, errors.New("auth data is expired")
	}

	// Преобразуем данные в структуру TelegramUser
	id, err := strconv.ParseInt(data["id"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid id: %w", err)
	}

	user := &TelegramUser{
		ID:        id,
		FirstName: data["first_name"],
		AuthDate:  authDate,
		Hash:      hash,
	}

	if lastName, ok := data["last_name"]; ok {
		user.LastName = lastName
	}

	if username, ok := data["username"]; ok {
		user.Username = username
	}

	if photoURL, ok := data["photo_url"]; ok {
		user.PhotoURL = photoURL
	}

	return user, nil
}

// SendMessage отправляет сообщение пользователю Telegram
func (c *Client) SendMessage(ctx context.Context, chatID int64, text string) error {
	// Формируем URL запроса
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", c.config.BotToken)

	// Формируем параметры запроса
	params := url.Values{}
	params.Add("chat_id", strconv.FormatInt(chatID, 10))
	params.Add("text", text)
	params.Add("parse_mode", "HTML")

	// Отправляем запрос
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(params.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Проверяем статус ответа
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API error: %s, status code: %d", string(body), resp.StatusCode)
	}

	// Парсим ответ
	var response struct {
		OK     bool   `json:"ok"`
		Result struct {
			MessageID int `json:"message_id"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if !response.OK {
		return errors.New("telegram API returned not OK status")
	}

	c.logger.Info("Telegram message sent", "chat_id", chatID, "message_id", response.Result.MessageID)
	return nil
}

// SendAuthCode отправляет код аутентификации пользователю Telegram
func (c *Client) SendAuthCode(ctx context.Context, chatID int64, code string) error {
	message := fmt.Sprintf("<b>Ваш код аутентификации:</b> %s\n\nКод действителен в течение 5 минут.", code)
	return c.SendMessage(ctx, chatID, message)
}

// SendPasswordResetCode отправляет код сброса пароля пользователю Telegram
func (c *Client) SendPasswordResetCode(ctx context.Context, chatID int64, code string) error {
	message := fmt.Sprintf("<b>Ваш код для сброса пароля:</b> %s\n\nКод действителен в течение 15 минут.", code)
	return c.SendMessage(ctx, chatID, message)
}

// SendSecurityAlert отправляет уведомление о безопасности пользователю Telegram
func (c *Client) SendSecurityAlert(ctx context.Context, chatID int64, alertType string, details map[string]string) error {
	var message string

	switch alertType {
	case "login":
		message = fmt.Sprintf("<b>Уведомление безопасности</b>\n\nВыполнен вход в ваш аккаунт:\n- Время: %s\n- IP: %s\n- Устройство: %s\n\nЕсли это были не вы, немедленно смените пароль.",
			details["time"], details["ip"], details["device"])
	case "password_changed":
		message = fmt.Sprintf("<b>Уведомление безопасности</b>\n\nПароль вашего аккаунта был изменен:\n- Время: %s\n- IP: %s\n\nЕсли это были не вы, немедленно обратитесь в службу поддержки.",
			details["time"], details["ip"])
	case "email_changed":
		message = fmt.Sprintf("<b>Уведомление безопасности</b>\n\nEmail вашего аккаунта был изменен:\n- Время: %s\n- Старый email: %s\n- Новый email: %s\n\nЕсли это были не вы, немедленно обратитесь в службу поддержки.",
			details["time"], details["old_email"], details["new_email"])
	default:
		message = fmt.Sprintf("<b>Уведомление безопасности</b>\n\nОбнаружена подозрительная активность в вашем аккаунте. Пожалуйста, проверьте историю входов и измените пароль при необходимости.")
	}

	return c.SendMessage(ctx, chatID, message)
}
