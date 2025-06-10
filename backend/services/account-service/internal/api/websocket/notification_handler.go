// File: backend/services/account-service/internal/api/websocket/notification_handler.go
// account-service/internal/api/websocket/notification_handler.go

package websocket

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/api/rest/middleware"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/errors"
)

const (
	// Время ожидания для записи сообщения клиенту
	writeWait = 10 * time.Second

	// Время между ping сообщениями
	pingPeriod = 60 * time.Second

	// Максимальный размер сообщения
	maxMessageSize = 1024
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// В продакшене здесь должна быть проверка источника запроса
		return true
	},
}

// Client представляет клиента WebSocket
type Client struct {
	hub    *NotificationHub
	conn   *websocket.Conn
	send   chan []byte
	userID uuid.UUID
	roles  []string
	mu     sync.Mutex
	topics map[string]bool
}

// NotificationHub управляет всеми активными WebSocket соединениями
type NotificationHub struct {
	// Зарегистрированные клиенты
	clients map[*Client]bool

	// Клиенты по ID пользователя
	userClients map[uuid.UUID][]*Client

	// Канал для регистрации новых клиентов
	register chan *Client

	// Канал для отмены регистрации клиентов
	unregister chan *Client

	// Канал для широковещательных сообщений
	broadcast chan *NotificationMessage

	// Мьютекс для синхронизации доступа к картам
	mu sync.RWMutex
}

// NotificationMessage представляет сообщение уведомления
type NotificationMessage struct {
	Type      string          `json:"type"`
	Topic     string          `json:"topic"`
	Data      json.RawMessage `json:"data"`
	Timestamp time.Time       `json:"timestamp"`
	UserID    *uuid.UUID      `json:"user_id,omitempty"` // Целевой пользователь или nil для широковещательных сообщений
	Roles     []string        `json:"roles,omitempty"`   // Целевые роли или nil для всех
}

// NewNotificationHub создает новый хаб уведомлений
func NewNotificationHub() *NotificationHub {
	return &NotificationHub{
		clients:     make(map[*Client]bool),
		userClients: make(map[uuid.UUID][]*Client),
		register:    make(chan *Client),
		unregister:  make(chan *Client),
		broadcast:   make(chan *NotificationMessage),
	}
}

// Run запускает цикл обработки сообщений хаба
func (h *NotificationHub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			if _, exists := h.userClients[client.userID]; !exists {
				h.userClients[client.userID] = make([]*Client, 0)
			}
			h.userClients[client.userID] = append(h.userClients[client.userID], client)
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)

				// Удаляем клиента из списка пользовательских клиентов
				if clients, exists := h.userClients[client.userID]; exists {
					for i, c := range clients {
						if c == client {
							h.userClients[client.userID] = append(clients[:i], clients[i+1:]...)
							break
						}
					}
					if len(h.userClients[client.userID]) == 0 {
						delete(h.userClients, client.userID)
					}
				}
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				// Проверяем, должен ли клиент получить это сообщение
				if h.shouldReceiveMessage(client, message) {
					select {
					case client.send <- h.serializeMessage(message):
					default:
						close(client.send)
						delete(h.clients, client)
					}
				}
			}
			h.mu.RUnlock()
		}
	}
}

// shouldReceiveMessage проверяет, должен ли клиент получить сообщение
func (h *NotificationHub) shouldReceiveMessage(client *Client, message *NotificationMessage) bool {
	// Если сообщение для конкретного пользователя
	if message.UserID != nil {
		return client.userID == *message.UserID
	}

	// Если сообщение для определенных ролей
	if len(message.Roles) > 0 {
		hasRole := false
		for _, requiredRole := range message.Roles {
			for _, clientRole := range client.roles {
				if requiredRole == clientRole {
					hasRole = true
					break
				}
			}
			if hasRole {
				break
			}
		}
		if !hasRole {
			return false
		}
	}

	// Проверяем подписку на топик
	client.mu.Lock()
	defer client.mu.Unlock()
	if message.Topic != "" {
		return client.topics[message.Topic]
	}

	return true
}

// serializeMessage сериализует сообщение в JSON
func (h *NotificationHub) serializeMessage(message *NotificationMessage) []byte {
	data, err := json.Marshal(message)
	if err != nil {
		log.Printf("Ошибка сериализации сообщения: %v", err)
		return []byte("{}")
	}
	return data
}

// Broadcast отправляет сообщение всем подключенным клиентам
func (h *NotificationHub) Broadcast(messageType string, topic string, data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Ошибка сериализации данных: %v", err)
		return
	}

	h.broadcast <- &NotificationMessage{
		Type:      messageType,
		Topic:     topic,
		Data:      jsonData,
		Timestamp: time.Now(),
	}
}

// SendToUser отправляет сообщение конкретному пользователю
func (h *NotificationHub) SendToUser(userID uuid.UUID, messageType string, topic string, data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Ошибка сериализации данных: %v", err)
		return
	}

	h.broadcast <- &NotificationMessage{
		Type:      messageType,
		Topic:     topic,
		Data:      jsonData,
		Timestamp: time.Now(),
		UserID:    &userID,
	}
}

// SendToRoles отправляет сообщение пользователям с определенными ролями
func (h *NotificationHub) SendToRoles(roles []string, messageType string, topic string, data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Ошибка сериализации данных: %v", err)
		return
	}

	h.broadcast <- &NotificationMessage{
		Type:      messageType,
		Topic:     topic,
		Data:      jsonData,
		Timestamp: time.Now(),
		Roles:     roles,
	}
}

// ServeWs обрабатывает WebSocket запросы от клиентов
func (h *NotificationHub) ServeWs(w http.ResponseWriter, r *http.Request) {
	// Проверяем JWT токен
	userID, err := middleware.GetUserIDFromRequest(r)
	if err != nil {
		http.Error(w, errors.NewUnauthorizedError("Требуется аутентификация").Error(), http.StatusUnauthorized)
		return
	}

	// Получаем роли пользователя
	roles := middleware.GetUserRolesFromRequest(r)

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Ошибка при установке WebSocket соединения: %v", err)
		return
	}

	client := &Client{
		hub:    h,
		conn:   conn,
		send:   make(chan []byte, 256),
		userID: userID,
		roles:  roles,
		topics: make(map[string]bool),
	}

	// Регистрируем клиента
	h.register <- client

	// Запускаем горутины для чтения и записи сообщений
	go client.writePump()
	go client.readPump()
}

// writePump отправляет сообщения клиенту
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// Хаб закрыл канал
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// ClientMessage представляет сообщение от клиента
type ClientMessage struct {
	Action string          `json:"action"`
	Topic  string          `json:"topic,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

// readPump читает сообщения от клиента
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pingPeriod))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pingPeriod))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("Ошибка: %v", err)
			}
			break
		}

		var clientMsg ClientMessage
		if err := json.Unmarshal(message, &clientMsg); err != nil {
			log.Printf("Ошибка разбора сообщения: %v", err)
			continue
		}

		// Обрабатываем сообщение от клиента
		switch clientMsg.Action {
		case "subscribe":
			if clientMsg.Topic != "" {
				c.mu.Lock()
				c.topics[clientMsg.Topic] = true
				c.mu.Unlock()

				// Отправляем подтверждение подписки
				c.send <- c.hub.serializeMessage(&NotificationMessage{
					Type:      "subscription_confirmed",
					Topic:     clientMsg.Topic,
					Timestamp: time.Now(),
				})
			}
		case "unsubscribe":
			if clientMsg.Topic != "" {
				c.mu.Lock()
				delete(c.topics, clientMsg.Topic)
				c.mu.Unlock()

				// Отправляем подтверждение отписки
				c.send <- c.hub.serializeMessage(&NotificationMessage{
					Type:      "unsubscription_confirmed",
					Topic:     clientMsg.Topic,
					Timestamp: time.Now(),
				})
			}
		}
	}
}

// NotificationHandler обработчик WebSocket уведомлений
type NotificationHandler struct {
	hub *NotificationHub
}

// NewNotificationHandler создает новый обработчик уведомлений
func NewNotificationHandler() *NotificationHandler {
	hub := NewNotificationHub()
	go hub.Run()
	return &NotificationHandler{
		hub: hub,
	}
}

// HandleWebSocket обрабатывает WebSocket соединения
func (h *NotificationHandler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	h.hub.ServeWs(w, r)
}

// NotifyAccountCreated отправляет уведомление о создании аккаунта
func (h *NotificationHandler) NotifyAccountCreated(ctx context.Context, accountID uuid.UUID) {
	// Отправляем уведомление администраторам
	h.hub.SendToRoles([]string{"admin"}, "account_created", "accounts", map[string]interface{}{
		"account_id": accountID,
		"action":     "created",
	})
}

// NotifyAccountUpdated отправляет уведомление об обновлении аккаунта
func (h *NotificationHandler) NotifyAccountUpdated(ctx context.Context, accountID uuid.UUID) {
	// Отправляем уведомление владельцу аккаунта
	h.hub.SendToUser(accountID, "account_updated", "accounts", map[string]interface{}{
		"account_id": accountID,
		"action":     "updated",
	})

	// Отправляем уведомление администраторам
	h.hub.SendToRoles([]string{"admin"}, "account_updated", "accounts", map[string]interface{}{
		"account_id": accountID,
		"action":     "updated",
	})
}

// NotifyAccountDeleted отправляет уведомление об удалении аккаунта
func (h *NotificationHandler) NotifyAccountDeleted(ctx context.Context, accountID uuid.UUID) {
	// Отправляем уведомление администраторам
	h.hub.SendToRoles([]string{"admin"}, "account_deleted", "accounts", map[string]interface{}{
		"account_id": accountID,
		"action":     "deleted",
	})
}

// NotifyProfileUpdated отправляет уведомление об обновлении профиля
func (h *NotificationHandler) NotifyProfileUpdated(ctx context.Context, accountID uuid.UUID) {
	// Отправляем уведомление владельцу профиля
	h.hub.SendToUser(accountID, "profile_updated", "profiles", map[string]interface{}{
		"account_id": accountID,
		"action":     "updated",
	})
}

// NotifyContactVerified отправляет уведомление о верификации контактной информации
func (h *NotificationHandler) NotifyContactVerified(ctx context.Context, accountID uuid.UUID, contactType string) {
	// Отправляем уведомление владельцу аккаунта
	h.hub.SendToUser(accountID, "contact_verified", "contacts", map[string]interface{}{
		"account_id": accountID,
		"type":       contactType,
		"action":     "verified",
	})
}

// NotifyAvatarUploaded отправляет уведомление о загрузке аватара
func (h *NotificationHandler) NotifyAvatarUploaded(ctx context.Context, accountID uuid.UUID, avatarID uuid.UUID) {
	// Отправляем уведомление владельцу аккаунта
	h.hub.SendToUser(accountID, "avatar_uploaded", "avatars", map[string]interface{}{
		"account_id": accountID,
		"avatar_id":  avatarID,
		"action":     "uploaded",
	})
}

// NotifySettingsUpdated отправляет уведомление об обновлении настроек
func (h *NotificationHandler) NotifySettingsUpdated(ctx context.Context, accountID uuid.UUID, category string) {
	// Отправляем уведомление владельцу аккаунта
	h.hub.SendToUser(accountID, "settings_updated", "settings", map[string]interface{}{
		"account_id": accountID,
		"category":   category,
		"action":     "updated",
	})
}
