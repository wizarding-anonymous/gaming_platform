// account-service\internal\domain\entity\profile_history.go

package entity

import (
	"time"

	"github.com/google/uuid"
)

// ProfileHistory представляет историю изменений профиля пользователя
type ProfileHistory struct {
	// ID - уникальный идентификатор записи истории
	ID uuid.UUID `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	// ProfileID - идентификатор профиля, к которому относится запись
	ProfileID uuid.UUID `json:"profile_id" gorm:"type:uuid;not null;index"`
	// FieldName - название измененного поля
	FieldName string `json:"field_name" gorm:"size:100;not null"`
	// OldValue - предыдущее значение поля
	OldValue string `json:"old_value" gorm:"size:1000"`
	// NewValue - новое значение поля
	NewValue string `json:"new_value" gorm:"size:1000"`
	// ChangedByAccountID - идентификатор аккаунта, который внес изменение
	ChangedByAccountID uuid.UUID `json:"changed_by_account_id" gorm:"type:uuid;not null"`
	// ChangedAt - время внесения изменения
	ChangedAt time.Time `json:"changed_at" gorm:"not null;default:now()"`
}

// NewProfileHistory создает новую запись истории изменений профиля
func NewProfileHistory(profileID uuid.UUID, fieldName string, oldValue string, newValue string, changedByAccountID uuid.UUID) *ProfileHistory {
	return &ProfileHistory{
		ID:                uuid.New(),
		ProfileID:         profileID,
		FieldName:         fieldName,
		OldValue:          oldValue,
		NewValue:          newValue,
		ChangedByAccountID: changedByAccountID,
		ChangedAt:         time.Now(),
	}
}
