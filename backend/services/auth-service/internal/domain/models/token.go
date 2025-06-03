package models

import (
	"time"

	"github.com/google/uuid"
)

// Token представляет модель токена в системе
type Token struct {
	ID        uuid.UUID `json:"id" db:"id"`
	UserID    uuid.UUID `json:"user_id" db:"user_id"`
	TokenType string    `json:"token_type" db:"token_type"`
	TokenValue string   `json:"-" db:"token_value"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	DeviceInfo *DeviceInfo `json:"device_info,omitempty" db:"-"`
}

// TokenType определяет типы токенов в системе
type TokenType string

const (
	TokenTypeAccess       TokenType = "access"
	TokenTypeRefresh      TokenType = "refresh"
	TokenTypeEmailVerify  TokenType = "email_verify"
	TokenTypePasswordReset TokenType = "password_reset"
)

// DeviceInfo содержит информацию об устройстве, с которого был выполнен вход
type DeviceInfo struct {
	IP        string    `json:"ip" db:"ip"`
	UserAgent string    `json:"user_agent" db:"user_agent"`
	DeviceID  string    `json:"device_id" db:"device_id"`
	LastUsed  time.Time `json:"last_used" db:"last_used"`
}

// TokenPair представляет пару токенов (access и refresh)
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresIn    int       `json:"expires_in"` // Время жизни access токена в секундах
	TokenType    string    `json:"token_type"` // Обычно "Bearer"
}

// RefreshTokenRequest представляет запрос на обновление токена
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// ValidateTokenRequest представляет запрос на валидацию токена
type ValidateTokenRequest struct {
	Token string `json:"token" validate:"required"`
}

// ValidateTokenResponse представляет ответ на валидацию токена
type ValidateTokenResponse struct {
	Valid  bool      `json:"valid"`
	UserID uuid.UUID `json:"user_id,omitempty"`
	Roles  []string  `json:"roles,omitempty"`
}

// NewToken создает новую модель токена
func NewToken(userID uuid.UUID, tokenType TokenType, tokenValue string, expiresIn time.Duration) Token {
	now := time.Now()
	return Token{
		ID:         uuid.New(),
		UserID:     userID,
		TokenType:  string(tokenType),
		TokenValue: tokenValue,
		ExpiresAt:  now.Add(expiresIn),
		CreatedAt:  now,
		UpdatedAt:  now,
	}
}

// IsExpired проверяет, истек ли срок действия токена
func (t Token) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsRevoked проверяет, был ли токен отозван
func (t Token) IsRevoked() bool {
	return t.RevokedAt != nil
}

// IsValid проверяет, действителен ли токен
func (t Token) IsValid() bool {
	return !t.IsExpired() && !t.IsRevoked()
}
