// File: backend/services/account-service/internal/api/presenter/account_presenter.go
// account-service/internal/api/presenter/account_presenter.go
package presenter

import (
	"time"

	"github.com/google/uuid"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/entity"
)

// AccountResponse DTO для ответа с информацией об аккаунте
type AccountResponse struct {
	ID        uuid.UUID `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ProfileResponse DTO для ответа с информацией о профиле
type ProfileResponse struct {
	ID         uuid.UUID `json:"id"`
	AccountID  uuid.UUID `json:"account_id"`
	Nickname   string    `json:"nickname"`
	RealName   string    `json:"real_name,omitempty"`
	Bio        string    `json:"bio,omitempty"`
	Country    string    `json:"country,omitempty"`
	City       string    `json:"city,omitempty"`
	AvatarURL  string    `json:"avatar_url,omitempty"`
	BannerURL  string    `json:"banner_url,omitempty"`
	Visibility string    `json:"visibility"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// ContactInfoResponse DTO для ответа с контактной информацией
type ContactInfoResponse struct {
	ID         uuid.UUID `json:"id"`
	AccountID  uuid.UUID `json:"account_id"`
	Type       string    `json:"type"`
	Value      string    `json:"value"`
	IsPrimary  bool      `json:"is_primary"`
	IsVerified bool      `json:"is_verified"`
	Visibility string    `json:"visibility"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// SettingResponse DTO для ответа с настройками
type SettingResponse struct {
	ID        uuid.UUID              `json:"id"`
	AccountID uuid.UUID              `json:"account_id"`
	Category  string                 `json:"category"`
	Settings  map[string]interface{} `json:"settings"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// AvatarResponse DTO для ответа с информацией об аватаре
type AvatarResponse struct {
	ID        uuid.UUID `json:"id"`
	AccountID uuid.UUID `json:"account_id"`
	Type      string    `json:"type"`
	URL       string    `json:"url"`
	Filename  string    `json:"filename"`
	Size      int64     `json:"size"`
	MimeType  string    `json:"mime_type"`
	Width     int       `json:"width"`
	Height    int       `json:"height"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AuthMethodResponse DTO для ответа с информацией о методе аутентификации
type AuthMethodResponse struct {
	ID         uuid.UUID `json:"id"`
	AccountID  uuid.UUID `json:"account_id"`
	Type       string    `json:"type"`
	Identifier string    `json:"identifier"`
	Provider   string    `json:"provider,omitempty"`
	IsVerified bool      `json:"is_verified"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// ToAccountResponse преобразует сущность Account в AccountResponse
func ToAccountResponse(account *entity.Account) *AccountResponse {
	if account == nil {
		return nil
	}
	return &AccountResponse{
		ID:        account.ID,
		Username:  account.Username,
		Email:     account.Email,
		Role:      string(account.Role),
		Status:    string(account.Status),
		CreatedAt: account.CreatedAt,
		UpdatedAt: account.UpdatedAt,
	}
}

// ToProfileResponse преобразует сущность Profile в ProfileResponse
func ToProfileResponse(profile *entity.Profile) *ProfileResponse {
	if profile == nil {
		return nil
	}
	return &ProfileResponse{
		ID:         profile.ID,
		AccountID:  profile.AccountID,
		Nickname:   profile.Nickname,
		RealName:   profile.RealName,
		Bio:        profile.Bio,
		Country:    profile.Country,
		City:       profile.City,
		AvatarURL:  profile.AvatarURL,
		BannerURL:  profile.BannerURL,
		Visibility: string(profile.Visibility),
		CreatedAt:  profile.CreatedAt,
		UpdatedAt:  profile.UpdatedAt,
	}
}

// ToContactInfoResponse преобразует сущность ContactInfo в ContactInfoResponse
func ToContactInfoResponse(contactInfo *entity.ContactInfo) *ContactInfoResponse {
	if contactInfo == nil {
		return nil
	}
	return &ContactInfoResponse{
		ID:         contactInfo.ID,
		AccountID:  contactInfo.AccountID,
		Type:       string(contactInfo.Type),
		Value:      contactInfo.Value,
		IsPrimary:  contactInfo.IsPrimary,
		IsVerified: contactInfo.IsVerified,
		Visibility: string(contactInfo.Visibility),
		CreatedAt:  contactInfo.CreatedAt,
		UpdatedAt:  contactInfo.UpdatedAt,
	}
}

// ToContactInfoListResponse преобразует список сущностей ContactInfo в список ContactInfoResponse
func ToContactInfoListResponse(contactInfos []*entity.ContactInfo) []*ContactInfoResponse {
	responses := make([]*ContactInfoResponse, len(contactInfos))
	for i, contactInfo := range contactInfos {
		responses[i] = ToContactInfoResponse(contactInfo)
	}
	return responses
}

// ToSettingResponse преобразует сущность Setting в SettingResponse
func ToSettingResponse(setting *entity.Setting) *SettingResponse {
	if setting == nil {
		return nil
	}
	return &SettingResponse{
		ID:        setting.ID,
		AccountID: setting.AccountID,
		Category:  string(setting.Category),
		Settings:  setting.Settings,
		CreatedAt: setting.CreatedAt,
		UpdatedAt: setting.UpdatedAt,
	}
}

// ToSettingListResponse преобразует список сущностей Setting в список SettingResponse
func ToSettingListResponse(settings []*entity.Setting) []*SettingResponse {
	responses := make([]*SettingResponse, len(settings))
	for i, setting := range settings {
		responses[i] = ToSettingResponse(setting)
	}
	return responses
}

// ToAvatarResponse преобразует сущность Avatar в AvatarResponse
func ToAvatarResponse(avatar *entity.Avatar) *AvatarResponse {
	if avatar == nil {
		return nil
	}
	return &AvatarResponse{
		ID:        avatar.ID,
		AccountID: avatar.AccountID,
		Type:      string(avatar.Type),
		URL:       avatar.URL,
		Filename:  avatar.Filename,
		Size:      avatar.Size,
		MimeType:  avatar.MimeType,
		Width:     avatar.Width,
		Height:    avatar.Height,
		IsActive:  avatar.IsActive,
		CreatedAt: avatar.CreatedAt,
		UpdatedAt: avatar.UpdatedAt,
	}
}

// ToAvatarListResponse преобразует список сущностей Avatar в список AvatarResponse
func ToAvatarListResponse(avatars []*entity.Avatar) []*AvatarResponse {
	responses := make([]*AvatarResponse, len(avatars))
	for i, avatar := range avatars {
		responses[i] = ToAvatarResponse(avatar)
	}
	return responses
}

// ToAuthMethodResponse преобразует сущность AuthMethod в AuthMethodResponse
func ToAuthMethodResponse(authMethod *entity.AuthMethod) *AuthMethodResponse {
	if authMethod == nil {
		return nil
	}
	return &AuthMethodResponse{
		ID:         authMethod.ID,
		AccountID:  authMethod.AccountID,
		Type:       string(authMethod.Type),
		Identifier: authMethod.Identifier,
		Provider:   string(authMethod.Provider),
		IsVerified: authMethod.IsVerified,
		CreatedAt:  authMethod.CreatedAt,
		UpdatedAt:  authMethod.UpdatedAt,
	}
}

// ToAuthMethodListResponse преобразует список сущностей AuthMethod в список AuthMethodResponse
func ToAuthMethodListResponse(authMethods []*entity.AuthMethod) []*AuthMethodResponse {
	responses := make([]*AuthMethodResponse, len(authMethods))
	for i, authMethod := range authMethods {
		responses[i] = ToAuthMethodResponse(authMethod)
	}
	return responses
}

// PaginatedResponse DTO для ответа с пагинацией
type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Total      int64       `json:"total"`
	Page       int         `json:"page"`
	PerPage    int         `json:"per_page"`
	TotalPages int         `json:"total_pages"`
}

// ErrorResponse DTO для ответа с ошибкой
type ErrorResponse struct {
	Error string `json:"error"`
	Code  int    `json:"code,omitempty"`
}

// SuccessResponse DTO для ответа об успехе
type SuccessResponse struct {
	Message string `json:"message"`
}
