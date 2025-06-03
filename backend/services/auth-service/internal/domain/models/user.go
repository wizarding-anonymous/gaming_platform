package models

import (
	"time"

	"github.com/google/uuid"
)

// User представляет модель пользователя в системе
type User struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	Email           string     `json:"email" db:"email"`
	Username        string     `json:"username" db:"username"`
	PasswordHash    string     `json:"-" db:"password_hash"`
	EmailVerified   bool       `json:"email_verified" db:"email_verified"`
	TwoFactorSecret string     `json:"-" db:"two_factor_secret"`
	TwoFactorEnabled bool      `json:"two_factor_enabled" db:"two_factor_enabled"`
	TelegramID      *string    `json:"telegram_id,omitempty" db:"telegram_id"`
	Status          string     `json:"status" db:"status"`
	LastLoginAt     *time.Time `json:"last_login_at,omitempty" db:"last_login_at"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
	Roles           []Role     `json:"roles,omitempty" db:"-"`
}

// UserStatus определяет возможные статусы пользователя
type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusInactive UserStatus = "inactive"
	UserStatusBlocked  UserStatus = "blocked"
	UserStatusDeleted  UserStatus = "deleted"
)

// CreateUserRequest представляет запрос на создание нового пользователя
type CreateUserRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Username string `json:"username" validate:"required,min=3,max=50"`
	Password string `json:"password" validate:"required,min=8,max=100"`
}

// UpdateUserRequest представляет запрос на обновление пользователя
type UpdateUserRequest struct {
	Username string `json:"username" validate:"omitempty,min=3,max=50"`
	Status   string `json:"status" validate:"omitempty,oneof=active inactive blocked"`
}

// LoginRequest представляет запрос на аутентификацию
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// TelegramLoginRequest представляет запрос на аутентификацию через Telegram
type TelegramLoginRequest struct {
	ID        int64  `json:"id" validate:"required"`
	FirstName string `json:"first_name" validate:"required"`
	Username  string `json:"username" validate:"required"`
	PhotoURL  string `json:"photo_url" validate:"omitempty,url"`
	AuthDate  int64  `json:"auth_date" validate:"required"`
	Hash      string `json:"hash" validate:"required"`
}

// VerifyEmailRequest представляет запрос на подтверждение email
type VerifyEmailRequest struct {
	Token string `json:"token" validate:"required"`
}

// ResendVerificationRequest представляет запрос на повторную отправку подтверждения
type ResendVerificationRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ForgotPasswordRequest представляет запрос на восстановление пароля
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ResetPasswordRequest представляет запрос на сброс пароля
type ResetPasswordRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=100"`
}

// TwoFactorEnableRequest представляет запрос на включение 2FA
type TwoFactorEnableRequest struct {
	Code string `json:"code" validate:"required,len=6,numeric"`
}

// TwoFactorVerifyRequest представляет запрос на проверку кода 2FA
type TwoFactorVerifyRequest struct {
	Code string `json:"code" validate:"required,len=6,numeric"`
}

// TwoFactorDisableRequest представляет запрос на отключение 2FA
type TwoFactorDisableRequest struct {
	Code string `json:"code" validate:"required,len=6,numeric"`
}

// UserResponse представляет ответ с информацией о пользователе
type UserResponse struct {
	ID              uuid.UUID `json:"id"`
	Email           string    `json:"email"`
	Username        string    `json:"username"`
	EmailVerified   bool      `json:"email_verified"`
	TwoFactorEnabled bool     `json:"two_factor_enabled"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	Roles           []string  `json:"roles,omitempty"`
}

// UserListResponse представляет ответ со списком пользователей
type UserListResponse struct {
	Users      []UserResponse `json:"users"`
	TotalCount int64          `json:"total_count"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
}

// NewUserFromRequest создает новую модель пользователя из запроса
func NewUserFromRequest(req CreateUserRequest) User {
	now := time.Now()
	return User{
		ID:            uuid.New(),
		Email:         req.Email,
		Username:      req.Username,
		EmailVerified: false,
		Status:        string(UserStatusActive),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

// ToResponse преобразует модель пользователя в ответ API
func (u User) ToResponse() UserResponse {
	roles := make([]string, 0, len(u.Roles))
	for _, role := range u.Roles {
		roles = append(roles, role.Name)
	}

	return UserResponse{
		ID:              u.ID,
		Email:           u.Email,
		Username:        u.Username,
		EmailVerified:   u.EmailVerified,
		TwoFactorEnabled: u.TwoFactorEnabled,
		Status:          u.Status,
		CreatedAt:       u.CreatedAt,
		UpdatedAt:       u.UpdatedAt,
		Roles:           roles,
	}
}
