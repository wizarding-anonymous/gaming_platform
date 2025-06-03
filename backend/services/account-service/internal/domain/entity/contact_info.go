// account-service/internal/domain/entity/contact_info.go
package entity

import (
"time"

"github.com/google/uuid"
)

// ContactType представляет тип контактной информации
type ContactType string

const (
// ContactTypeEmail - электронная почта
ContactTypeEmail ContactType = "email"
// ContactTypePhone - телефон
ContactTypePhone ContactType = "phone"
// ContactTypeTelegram - Telegram
ContactTypeTelegram ContactType = "telegram"
// ContactTypeDiscord - Discord
ContactTypeDiscord ContactType = "discord"
// ContactTypeVK - ВКонтакте
ContactTypeVK ContactType = "vk"
)

// ContactVisibility представляет уровень видимости контактной информации
type ContactVisibility string

const (
// ContactVisibilityPublic - публичный контакт
ContactVisibilityPublic ContactVisibility = "public"
// ContactVisibilityFriendsOnly - видимый только для друзей
ContactVisibilityFriendsOnly ContactVisibility = "friends_only"
// ContactVisibilityPrivate - приватный контакт
ContactVisibilityPrivate ContactVisibility = "private"
)

// ContactInfo представляет контактную информацию пользователя
type ContactInfo struct {
ID                 uuid.UUID        `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
AccountID          uuid.UUID        `json:"account_id" gorm:"type:uuid;not null;index"`
Type               ContactType      `json:"type" gorm:"size:20;not null"`
Value              string           `json:"value" gorm:"size:255;not null"`
Visibility         ContactVisibility `json:"visibility" gorm:"size:20;not null;default:'private'"`
Verified           bool             `json:"verified" gorm:"not null;default:false"`
VerificationCode   string           `json:"verification_code,omitempty" gorm:"size:20"`
VerificationExpiry *time.Time       `json:"verification_expiry,omitempty"`
VerificationAttempts int            `json:"verification_attempts" gorm:"not null;default:0"`
IsPrimary          bool             `json:"is_primary" gorm:"not null;default:false"`
CreatedAt          time.Time        `json:"created_at" gorm:"not null;default:now()"`
UpdatedAt          time.Time        `json:"updated_at" gorm:"not null;default:now()"`
}

// NewContactInfo создает новую контактную информацию
func NewContactInfo(accountID uuid.UUID, contactType ContactType, value string) *ContactInfo {
return &ContactInfo{
ID:                uuid.New(),
AccountID:         accountID,
Type:              contactType,
Value:             value,
Visibility:        ContactVisibilityPrivate,
Verified:          false,
VerificationAttempts: 0,
IsPrimary:         false,
CreatedAt:         time.Now(),
UpdatedAt:         time.Now(),
}
}

// SetVerificationCode устанавливает код верификации и срок его действия
func (c *ContactInfo) SetVerificationCode(code string, expiryMinutes int) {
c.VerificationCode = code
expiry := time.Now().Add(time.Duration(expiryMinutes) * time.Minute)
c.VerificationExpiry = &expiry
c.UpdatedAt = time.Now()
}

// Verify верифицирует контактную информацию
func (c *ContactInfo) Verify() {
c.Verified = true
c.VerificationCode = ""
c.VerificationExpiry = nil
c.UpdatedAt = time.Now()
}

// IsVerified проверяет, верифицирована ли контактная информация
func (c *ContactInfo) IsVerified() bool {
return c.Verified
}

// IsVerificationExpired проверяет, истек ли срок действия кода верификации
func (c *ContactInfo) IsVerificationExpired() bool {
if c.VerificationExpiry == nil {
return true
}
return time.Now().After(*c.VerificationExpiry)
}

// IncrementVerificationAttempts увеличивает счетчик попыток верификации
func (c *ContactInfo) IncrementVerificationAttempts() {
c.VerificationAttempts++
c.UpdatedAt = time.Now()
}

// SetPrimary устанавливает контакт как основной
func (c *ContactInfo) SetPrimary() {
c.IsPrimary = true
c.UpdatedAt = time.Now()
}

// UnsetPrimary снимает статус основного контакта
func (c *ContactInfo) UnsetPrimary() {
c.IsPrimary = false
c.UpdatedAt = time.Now()
}

// UpdateValue обновляет значение контакта
func (c *ContactInfo) UpdateValue(value string) {
c.Value = value
c.Verified = false // При изменении значения требуется повторная верификация
c.UpdatedAt = time.Now()
}

// UpdateVisibility обновляет видимость контакта
func (c *ContactInfo) UpdateVisibility(visibility ContactVisibility) {
c.Visibility = visibility
c.UpdatedAt = time.Now()
}

// IsPublic проверяет, является ли контакт публичным
func (c *ContactInfo) IsPublic() bool {
return c.Visibility == ContactVisibilityPublic
}

// IsFriendsOnly проверяет, видим ли контакт только для друзей
func (c *ContactInfo) IsFriendsOnly() bool {
return c.Visibility == ContactVisibilityFriendsOnly
}

// IsPrivate проверяет, является ли контакт приватным
func (c *ContactInfo) IsPrivate() bool {
return c.Visibility == ContactVisibilityPrivate
}
