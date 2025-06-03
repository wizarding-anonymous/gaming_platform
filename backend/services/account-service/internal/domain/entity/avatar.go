// account-service/internal/domain/entity/avatar.go
package entity

import (
"time"

"github.com/google/uuid"
)

// AvatarType представляет тип аватара
type AvatarType string

const (
// AvatarTypeProfile - аватар профиля
AvatarTypeProfile AvatarType = "profile"
// AvatarTypeBanner - баннер профиля
AvatarTypeBanner AvatarType = "banner"
)

// Avatar представляет аватар пользователя
type Avatar struct {
ID        uuid.UUID  `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
AccountID uuid.UUID  `json:"account_id" gorm:"type:uuid;not null;index"`
Type      AvatarType `json:"type" gorm:"size:20;not null"`
URL       string     `json:"url" gorm:"size:255;not null"`
Filename  string     `json:"filename" gorm:"size:255;not null"`
Size      int64      `json:"size" gorm:"not null"`
MimeType  string     `json:"mime_type" gorm:"size:50;not null"`
Width     int        `json:"width" gorm:"not null"`
Height    int        `json:"height" gorm:"not null"`
IsActive  bool       `json:"is_active" gorm:"not null;default:true"`
CreatedAt time.Time  `json:"created_at" gorm:"not null;default:now()"`
UpdatedAt time.Time  `json:"updated_at" gorm:"not null;default:now()"`
}

// NewAvatar создает новый аватар
func NewAvatar(accountID uuid.UUID, avatarType AvatarType, url, filename string, size int64, mimeType string, width, height int) *Avatar {
return &Avatar{
ID:        uuid.New(),
AccountID: accountID,
Type:      avatarType,
URL:       url,
Filename:  filename,
Size:      size,
MimeType:  mimeType,
Width:     width,
Height:    height,
IsActive:  true,
CreatedAt: time.Now(),
UpdatedAt: time.Now(),
}
}

// Deactivate деактивирует аватар
func (a *Avatar) Deactivate() {
a.IsActive = false
a.UpdatedAt = time.Now()
}

// Activate активирует аватар
func (a *Avatar) Activate() {
a.IsActive = true
a.UpdatedAt = time.Now()
}

// UpdateURL обновляет URL аватара
func (a *Avatar) UpdateURL(url string) {
a.URL = url
a.UpdatedAt = time.Now()
}

// IsProfileAvatar проверяет, является ли аватар профильным
func (a *Avatar) IsProfileAvatar() bool {
return a.Type == AvatarTypeProfile
}

// IsBannerAvatar проверяет, является ли аватар баннером
func (a *Avatar) IsBannerAvatar() bool {
return a.Type == AvatarTypeBanner
}
