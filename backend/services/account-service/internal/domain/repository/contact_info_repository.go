// File: backend/services/account-service/internal/domain/repository/contact_info_repository.go
// account-service/internal/domain/repository/contact_info_repository.go
package repository

import (
"context"

"github.com/google/uuid"
"github.com/steamru/account-service/internal/domain/entity"
)

// ContactInfoFilter представляет фильтр для поиска контактной информации
type ContactInfoFilter struct {
AccountID  uuid.UUID
Type       *entity.ContactType
Visibility *entity.ContactVisibility
Verified   *bool
IsPrimary  *bool
Limit      int
Offset     int
}

// ContactInfoRepository представляет интерфейс репозитория для работы с контактной информацией
type ContactInfoRepository interface {
// Create создает новую контактную информацию
Create(ctx context.Context, contactInfo *entity.ContactInfo) error

// GetByID получает контактную информацию по ID
GetByID(ctx context.Context, id uuid.UUID) (*entity.ContactInfo, error)

// GetByAccountID получает всю контактную информацию пользователя
GetByAccountID(ctx context.Context, accountID uuid.UUID) ([]*entity.ContactInfo, error)

// GetByAccountIDAndType получает контактную информацию пользователя по типу
GetByAccountIDAndType(ctx context.Context, accountID uuid.UUID, contactType entity.ContactType) ([]*entity.ContactInfo, error)

// GetPrimaryByAccountIDAndType получает основную контактную информацию пользователя по типу
GetPrimaryByAccountIDAndType(ctx context.Context, accountID uuid.UUID, contactType entity.ContactType) (*entity.ContactInfo, error)

// GetByTypeAndValue получает контактную информацию по типу и значению
GetByTypeAndValue(ctx context.Context, contactType entity.ContactType, value string) (*entity.ContactInfo, error)

// Update обновляет контактную информацию
Update(ctx context.Context, contactInfo *entity.ContactInfo) error

// Delete удаляет контактную информацию
Delete(ctx context.Context, id uuid.UUID) error

// DeleteByAccountID удаляет всю контактную информацию пользователя
DeleteByAccountID(ctx context.Context, accountID uuid.UUID) error

// List получает список контактной информации по фильтру
List(ctx context.Context, filter ContactInfoFilter) ([]*entity.ContactInfo, error)

// Exists проверяет существование контактной информации по ID
Exists(ctx context.Context, id uuid.UUID) (bool, error)

// ExistsByTypeAndValue проверяет существование контактной информации по типу и значению
ExistsByTypeAndValue(ctx context.Context, contactType entity.ContactType, value string) (bool, error)

// UpdateValue обновляет значение контактной информации
UpdateValue(ctx context.Context, id uuid.UUID, value string) error

// UpdateVisibility обновляет видимость контактной информации
UpdateVisibility(ctx context.Context, id uuid.UUID, visibility entity.ContactVisibility) error

// SetVerificationCode устанавливает код верификации и срок его действия
SetVerificationCode(ctx context.Context, id uuid.UUID, code string, expiryMinutes int) error

// Verify помечает контактную информацию как верифицированную
Verify(ctx context.Context, id uuid.UUID) error

// IncrementVerificationAttempts увеличивает счетчик попыток верификации
IncrementVerificationAttempts(ctx context.Context, id uuid.UUID) error

// SetPrimary устанавливает контакт как основной
SetPrimary(ctx context.Context, id uuid.UUID) error

// UnsetPrimaryByAccountIDAndType снимает статус основного контакта для всех контактов указанного типа
UnsetPrimaryByAccountIDAndType(ctx context.Context, accountID uuid.UUID, contactType entity.ContactType) error
}
