// File: backend/services/account-service/internal/domain/entity/setting.go
// account-service/internal/domain/entity/setting.go
package entity

import (
"encoding/json"
"time"

"github.com/google/uuid"
)

// SettingCategory представляет категорию настроек
type SettingCategory string

const (
// SettingCategoryPrivacy - настройки приватности
SettingCategoryPrivacy SettingCategory = "privacy"
// SettingCategoryNotification - настройки уведомлений
SettingCategoryNotification SettingCategory = "notification"
// SettingCategoryInterface - настройки интерфейса
SettingCategoryInterface SettingCategory = "interface"
// SettingCategorySecurity - настройки безопасности
SettingCategorySecurity SettingCategory = "security"
)

// Setting представляет настройки пользователя
type Setting struct {
ID        uuid.UUID       `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
AccountID uuid.UUID       `json:"account_id" gorm:"type:uuid;not null;uniqueIndex"`
Category  SettingCategory `json:"category" gorm:"size:20;not null"`
Settings  map[string]interface{} `json:"settings" gorm:"type:jsonb;not null;default:'{}'"`
CreatedAt time.Time       `json:"created_at" gorm:"not null;default:now()"`
UpdatedAt time.Time       `json:"updated_at" gorm:"not null;default:now()"`
}

// NewSetting создает новые настройки пользователя
func NewSetting(accountID uuid.UUID, category SettingCategory) *Setting {
return &Setting{
ID:        uuid.New(),
AccountID: accountID,
Category:  category,
Settings:  make(map[string]interface{}),
CreatedAt: time.Now(),
UpdatedAt: time.Now(),
}
}

// GetSetting получает значение настройки
func (s *Setting) GetSetting(key string) (interface{}, bool) {
value, exists := s.Settings[key]
return value, exists
}

// SetSetting устанавливает значение настройки
func (s *Setting) SetSetting(key string, value interface{}) {
s.Settings[key] = value
s.UpdatedAt = time.Now()
}

// RemoveSetting удаляет настройку
func (s *Setting) RemoveSetting(key string) {
delete(s.Settings, key)
s.UpdatedAt = time.Now()
}

// HasSetting проверяет наличие настройки
func (s *Setting) HasSetting(key string) bool {
_, exists := s.Settings[key]
return exists
}

// MarshalSettings сериализует настройки в JSON
func (s *Setting) MarshalSettings() ([]byte, error) {
return json.Marshal(s.Settings)
}

// UnmarshalSettings десериализует настройки из JSON
func (s *Setting) UnmarshalSettings(data []byte) error {
return json.Unmarshal(data, &s.Settings)
}

// GetBoolSetting получает булево значение настройки
func (s *Setting) GetBoolSetting(key string, defaultValue bool) bool {
if value, exists := s.Settings[key]; exists {
if boolValue, ok := value.(bool); ok {
return boolValue
}
}
return defaultValue
}

// GetStringSetting получает строковое значение настройки
func (s *Setting) GetStringSetting(key string, defaultValue string) string {
if value, exists := s.Settings[key]; exists {
if strValue, ok := value.(string); ok {
return strValue
}
}
return defaultValue
}

// GetIntSetting получает целочисленное значение настройки
func (s *Setting) GetIntSetting(key string, defaultValue int) int {
if value, exists := s.Settings[key]; exists {
switch v := value.(type) {
case int:
return v
case float64:
return int(v)
}
}
return defaultValue
}

// ResetToDefaults сбрасывает настройки на значения по умолчанию
func (s *Setting) ResetToDefaults() {
s.Settings = make(map[string]interface{})

// Установка значений по умолчанию в зависимости от категории
switch s.Category {
case SettingCategoryPrivacy:
s.Settings["profile_visibility"] = "public"
s.Settings["show_online_status"] = true
s.Settings["show_activity"] = true
case SettingCategoryNotification:
s.Settings["email_notifications"] = true
s.Settings["push_notifications"] = true
s.Settings["friend_requests"] = true
s.Settings["messages"] = true
case SettingCategoryInterface:
s.Settings["theme"] = "light"
s.Settings["language"] = "ru"
s.Settings["compact_view"] = false
case SettingCategorySecurity:
s.Settings["two_factor_auth"] = false
s.Settings["login_notifications"] = true
s.Settings["session_timeout"] = 30
}

s.UpdatedAt = time.Now()
}
