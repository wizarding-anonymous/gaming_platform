// account-service/internal/domain/entity/auth_method.go
package entity

import (
"time"

"github.com/google/uuid"
)

// AuthMethodType представляет тип метода аутентификации
type AuthMethodType string

const (
// AuthMethodPassword - аутентификация по паролю
AuthMethodPassword AuthMethodType = "password"
// AuthMethodOAuth - аутентификация через OAuth
AuthMethodOAuth AuthMethodType = "oauth"
// AuthMethodTwoFactor - двухфакторная аутентификация
AuthMethodTwoFactor AuthMethodType = "2fa"
)

// AuthMethod представляет метод аутентификации пользователя
type AuthMethod struct {
ID        uuid.UUID      `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
AccountID uuid.UUID      `json:"account_id" gorm:"type:uuid;not null;index"`
Type      AuthMethodType `json:"type" gorm:"size:20;not null"`
Provider  string         `json:"provider" gorm:"size:50"`
Identifier string        `json:"identifier" gorm:"size:255"`
Secret    string         `json:"secret,omitempty" gorm:"size:255"` // Хеш пароля или токен
Verified  bool           `json:"verified" gorm:"not null;default:false"`
CreatedAt time.Time      `json:"created_at" gorm:"not null;default:now()"`
UpdatedAt time.Time      `json:"updated_at" gorm:"not null;default:now()"`
}

// NewPasswordAuthMethod создает новый метод аутентификации по паролю
func NewPasswordAuthMethod(accountID uuid.UUID, email, passwordHash string) *AuthMethod {
return &AuthMethod{
ID:         uuid.New(),
AccountID:  accountID,
Type:       AuthMethodPassword,
Provider:   "local",
Identifier: email,
Secret:     passwordHash,
Verified:   false,
CreatedAt:  time.Now(),
UpdatedAt:  time.Now(),
}
}

// NewOAuthAuthMethod создает новый метод аутентификации через OAuth
func NewOAuthAuthMethod(accountID uuid.UUID, provider, identifier, token string) *AuthMethod {
return &AuthMethod{
ID:         uuid.New(),
AccountID:  accountID,
Type:       AuthMethodOAuth,
Provider:   provider,
Identifier: identifier,
Secret:     token,
Verified:   true, // OAuth обычно уже верифицирован
CreatedAt:  time.Now(),
UpdatedAt:  time.Now(),
}
}

// NewTwoFactorAuthMethod создает новый метод двухфакторной аутентификации
func NewTwoFactorAuthMethod(accountID uuid.UUID, secret string) *AuthMethod {
return &AuthMethod{
ID:         uuid.New(),
AccountID:  accountID,
Type:       AuthMethodTwoFactor,
Provider:   "totp",
Identifier: "2fa",
Secret:     secret,
Verified:   false,
CreatedAt:  time.Now(),
UpdatedAt:  time.Now(),
}
}

// Verify помечает метод аутентификации как верифицированный
func (a *AuthMethod) Verify() {
a.Verified = true
a.UpdatedAt = time.Now()
}

// UpdateSecret обновляет секрет (пароль/токен) метода аутентификации
func (a *AuthMethod) UpdateSecret(secret string) {
a.Secret = secret
a.UpdatedAt = time.Now()
}

// IsVerified проверяет, верифицирован ли метод аутентификации
func (a *AuthMethod) IsVerified() bool {
return a.Verified
}
