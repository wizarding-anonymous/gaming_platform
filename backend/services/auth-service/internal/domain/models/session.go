package models

import (
	"time"

	"github.com/google/uuid"
)

// Session представляет модель сессии пользователя в системе
type Session struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	UserID       uuid.UUID  `json:"user_id" db:"user_id"`
	RefreshToken string     `json:"-" db:"refresh_token"`
	IP           string     `json:"ip" db:"ip"`
	UserAgent    string     `json:"user_agent" db:"user_agent"`
	DeviceID     string     `json:"device_id" db:"device_id"`
	ExpiresAt    time.Time  `json:"expires_at" db:"expires_at"`
	LastActivity time.Time  `json:"last_activity" db:"last_activity"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at" db:"updated_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
}

// SessionStatus определяет статусы сессии
type SessionStatus string

const (
	SessionStatusActive  SessionStatus = "active"
	SessionStatusExpired SessionStatus = "expired"
	SessionStatusRevoked SessionStatus = "revoked"
)

// SessionResponse представляет ответ с информацией о сессии
type SessionResponse struct {
	ID           uuid.UUID `json:"id"`
	IP           string    `json:"ip"`
	UserAgent    string    `json:"user_agent"`
	DeviceID     string    `json:"device_id"`
	LastActivity time.Time `json:"last_activity"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Status       string    `json:"status"`
}

// SessionListResponse представляет ответ со списком сессий
type SessionListResponse struct {
	Sessions   []SessionResponse `json:"sessions"`
	TotalCount int64             `json:"total_count"`
}

// LogoutRequest представляет запрос на выход из системы
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// LogoutAllRequest представляет запрос на выход из всех устройств
type LogoutAllRequest struct {
	ExceptCurrent bool `json:"except_current"`
}

// NewSession создает новую модель сессии
func NewSession(userID uuid.UUID, refreshToken, ip, userAgent, deviceID string, expiresIn time.Duration) Session {
	now := time.Now()
	return Session{
		ID:           uuid.New(),
		UserID:       userID,
		RefreshToken: refreshToken,
		IP:           ip,
		UserAgent:    userAgent,
		DeviceID:     deviceID,
		ExpiresAt:    now.Add(expiresIn),
		LastActivity: now,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// IsExpired проверяет, истек ли срок действия сессии
func (s Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsRevoked проверяет, была ли сессия отозвана
func (s Session) IsRevoked() bool {
	return s.RevokedAt != nil
}

// IsValid проверяет, действительна ли сессия
func (s Session) IsValid() bool {
	return !s.IsExpired() && !s.IsRevoked()
}

// GetStatus возвращает статус сессии
func (s Session) GetStatus() SessionStatus {
	if s.IsRevoked() {
		return SessionStatusRevoked
	}
	if s.IsExpired() {
		return SessionStatusExpired
	}
	return SessionStatusActive
}

// ToResponse преобразует модель сессии в ответ API
func (s Session) ToResponse() SessionResponse {
	return SessionResponse{
		ID:           s.ID,
		IP:           s.IP,
		UserAgent:    s.UserAgent,
		DeviceID:     s.DeviceID,
		LastActivity: s.LastActivity,
		CreatedAt:    s.CreatedAt,
		ExpiresAt:    s.ExpiresAt,
		Status:       string(s.GetStatus()),
	}
}
