// File: backend/services/account-service/internal/domain/entity/profile.go
// account-service/internal/domain/entity/profile.go
package entity

import (
"time"

"github.com/google/uuid"
)

// ProfileVisibility представляет уровень видимости профиля
type ProfileVisibility string

const (
// ProfileVisibilityPublic - публичный профиль
ProfileVisibilityPublic ProfileVisibility = "public"
// ProfileVisibilityFriendsOnly - видимый только для друзей
ProfileVisibilityFriendsOnly ProfileVisibility = "friends_only"
// ProfileVisibilityPrivate - приватный профиль
ProfileVisibilityPrivate ProfileVisibility = "private"
)

// Profile представляет профиль пользователя
type Profile struct {
ID          uuid.UUID         `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
AccountID   uuid.UUID         `json:"account_id" gorm:"type:uuid;not null;uniqueIndex"`
Nickname    string            `json:"nickname" gorm:"size:50"`
RealName    string            `json:"real_name" gorm:"size:100"`
Bio         string            `json:"bio" gorm:"type:text"`
Country     string            `json:"country" gorm:"size:2"`
Language    string            `json:"language" gorm:"size:5"`
DateOfBirth *time.Time        `json:"date_of_birth,omitempty"`
AvatarURL   string            `json:"avatar_url" gorm:"size:255"`
BannerURL   string            `json:"banner_url" gorm:"size:255"`
Visibility  ProfileVisibility `json:"visibility" gorm:"size:20;not null;default:'public'"`
CreatedAt   time.Time         `json:"created_at" gorm:"not null;default:now()"`
UpdatedAt   time.Time         `json:"updated_at" gorm:"not null;default:now()"`
}

// NewProfile создает новый профиль пользователя
func NewProfile(accountID uuid.UUID, nickname string) *Profile {
return &Profile{
ID:         uuid.New(),
AccountID:  accountID,
Nickname:   nickname,
Visibility: ProfileVisibilityPublic,
CreatedAt:  time.Now(),
UpdatedAt:  time.Now(),
}
}

// UpdateNickname обновляет никнейм профиля
func (p *Profile) UpdateNickname(nickname string) {
p.Nickname = nickname
p.UpdatedAt = time.Now()
}

// UpdateRealName обновляет реальное имя профиля
func (p *Profile) UpdateRealName(realName string) {
p.RealName = realName
p.UpdatedAt = time.Now()
}

// UpdateBio обновляет биографию профиля
func (p *Profile) UpdateBio(bio string) {
p.Bio = bio
p.UpdatedAt = time.Now()
}

// UpdateCountry обновляет страну профиля
func (p *Profile) UpdateCountry(country string) {
p.Country = country
p.UpdatedAt = time.Now()
}

// UpdateLanguage обновляет язык профиля
func (p *Profile) UpdateLanguage(language string) {
p.Language = language
p.UpdatedAt = time.Now()
}

// UpdateDateOfBirth обновляет дату рождения профиля
func (p *Profile) UpdateDateOfBirth(dateOfBirth time.Time) {
p.DateOfBirth = &dateOfBirth
p.UpdatedAt = time.Now()
}

// UpdateAvatarURL обновляет URL аватара профиля
func (p *Profile) UpdateAvatarURL(avatarURL string) {
p.AvatarURL = avatarURL
p.UpdatedAt = time.Now()
}

// UpdateBannerURL обновляет URL баннера профиля
func (p *Profile) UpdateBannerURL(bannerURL string) {
p.BannerURL = bannerURL
p.UpdatedAt = time.Now()
}

// UpdateVisibility обновляет видимость профиля
func (p *Profile) UpdateVisibility(visibility ProfileVisibility) {
p.Visibility = visibility
p.UpdatedAt = time.Now()
}

// IsPublic проверяет, является ли профиль публичным
func (p *Profile) IsPublic() bool {
return p.Visibility == ProfileVisibilityPublic
}

// IsFriendsOnly проверяет, видим ли профиль только для друзей
func (p *Profile) IsFriendsOnly() bool {
return p.Visibility == ProfileVisibilityFriendsOnly
}

// IsPrivate проверяет, является ли профиль приватным
func (p *Profile) IsPrivate() bool {
return p.Visibility == ProfileVisibilityPrivate
}

// Anonymize анонимизирует данные профиля
func (p *Profile) Anonymize() {
anonymousID := uuid.New().String()
p.Nickname = "deleted_" + anonymousID[:8]
p.RealName = ""
p.Bio = ""
p.Country = ""
p.Language = ""
p.DateOfBirth = nil
p.AvatarURL = ""
p.BannerURL = ""
p.Visibility = ProfileVisibilityPrivate
p.UpdatedAt = time.Now()
}
