// File: backend/services/account-service/internal/infrastructure/repository/postgres/contact_info_repository.go
// account-service/internal/infrastructure/repository/postgres/contact_info_repository.go
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/entity"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/repository"
)

// ContactInfoModel представляет модель контактной информации в базе данных
type ContactInfoModel struct {
	ID                   uuid.UUID `gorm:"type:uuid;primary_key"`
	AccountID            uuid.UUID `gorm:"type:uuid;index"`
	Type                 string    `gorm:"type:varchar(20);not null"`
	Value                string    `gorm:"type:varchar(255);not null"`
	IsPrimary            bool      `gorm:"default:false"`
	IsVerified           bool      `gorm:"default:false"`
	Visibility           string    `gorm:"type:varchar(20);not null"`
	VerificationCode     string    `gorm:"type:varchar(50)"`
	VerificationExpires  *time.Time
	VerificationAttempts int       `gorm:"default:0"`
	CreatedAt            time.Time
	UpdatedAt            time.Time
	DeletedAt            *time.Time `gorm:"index"`
}

// TableName возвращает имя таблицы
func (ContactInfoModel) TableName() string {
	return "contact_info"
}

// ToEntity преобразует модель в сущность
func (m *ContactInfoModel) ToEntity() *entity.ContactInfo {
	contactInfo := &entity.ContactInfo{
		ID:                   m.ID,
		AccountID:            m.AccountID,
		Type:                 entity.ContactType(m.Type),
		Value:                m.Value,
		IsPrimary:            m.IsPrimary,
		IsVerified:           m.IsVerified,
		Visibility:           entity.Visibility(m.Visibility),
		VerificationCode:     m.VerificationCode,
		VerificationAttempts: m.VerificationAttempts,
		CreatedAt:            m.CreatedAt,
		UpdatedAt:            m.UpdatedAt,
	}
	if m.VerificationExpires != nil {
		contactInfo.VerificationExpires = *m.VerificationExpires
	}
	return contactInfo
}

// FromEntity преобразует сущность в модель
func (m *ContactInfoModel) FromEntity(contactInfo *entity.ContactInfo) {
	m.ID = contactInfo.ID
	m.AccountID = contactInfo.AccountID
	m.Type = string(contactInfo.Type)
	m.Value = contactInfo.Value
	m.IsPrimary = contactInfo.IsPrimary
	m.IsVerified = contactInfo.IsVerified
	m.Visibility = string(contactInfo.Visibility)
	m.VerificationCode = contactInfo.VerificationCode
	m.VerificationAttempts = contactInfo.VerificationAttempts
	if !contactInfo.VerificationExpires.IsZero() {
		m.VerificationExpires = &contactInfo.VerificationExpires
	}
	m.CreatedAt = contactInfo.CreatedAt
	m.UpdatedAt = contactInfo.UpdatedAt
}

// ContactInfoRepositoryImpl реализация репозитория для работы с контактной информацией
type ContactInfoRepositoryImpl struct {
	db *gorm.DB
}

// NewContactInfoRepository создает новый экземпляр репозитория для работы с контактной информацией
func NewContactInfoRepository(db *gorm.DB) repository.ContactInfoRepository {
	return &ContactInfoRepositoryImpl{
		db: db,
	}
}

// Create создает новую контактную информацию
func (r *ContactInfoRepositoryImpl) Create(ctx context.Context, contactInfo *entity.ContactInfo) error {
	model := &ContactInfoModel{}
	model.FromEntity(contactInfo)

	result := r.db.WithContext(ctx).Create(model)
	if result.Error != nil {
		return fmt.Errorf("failed to create contact info: %w", result.Error)
	}

	return nil
}

// GetByID получает контактную информацию по ID
func (r *ContactInfoRepositoryImpl) GetByID(ctx context.Context, id uuid.UUID) (*entity.ContactInfo, error) {
	var model ContactInfoModel
	result := r.db.WithContext(ctx).First(&model, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, repository.ErrContactInfoNotFound
		}
		return nil, fmt.Errorf("failed to get contact info by ID: %w", result.Error)
	}

	return model.ToEntity(), nil
}

// GetByAccountID получает всю контактную информацию пользователя
func (r *ContactInfoRepositoryImpl) GetByAccountID(ctx context.Context, accountID uuid.UUID) ([]*entity.ContactInfo, error) {
	var models []ContactInfoModel
	result := r.db.WithContext(ctx).Where("account_id = ?", accountID).Find(&models)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to get contact info by account ID: %w", result.Error)
	}

	contactInfos := make([]*entity.ContactInfo, len(models))
	for i, model := range models {
		contactInfos[i] = model.ToEntity()
	}

	return contactInfos, nil
}

// GetByAccountIDAndType получает контактную информацию пользователя определенного типа
func (r *ContactInfoRepositoryImpl) GetByAccountIDAndType(ctx context.Context, accountID uuid.UUID, contactType entity.ContactType) ([]*entity.ContactInfo, error) {
	var models []ContactInfoModel
	result := r.db.WithContext(ctx).Where("account_id = ? AND type = ?", accountID, string(contactType)).Find(&models)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to get contact info by account ID and type: %w", result.Error)
	}

	contactInfos := make([]*entity.ContactInfo, len(models))
	for i, model := range models {
		contactInfos[i] = model.ToEntity()
	}

	return contactInfos, nil
}

// GetPrimaryByAccountIDAndType получает основную контактную информацию пользователя определенного типа
func (r *ContactInfoRepositoryImpl) GetPrimaryByAccountIDAndType(ctx context.Context, accountID uuid.UUID, contactType entity.ContactType) (*entity.ContactInfo, error) {
	var model ContactInfoModel
	result := r.db.WithContext(ctx).First(&model, "account_id = ? AND type = ? AND is_primary = ?", accountID, string(contactType), true)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, repository.ErrContactInfoNotFound
		}
		return nil, fmt.Errorf("failed to get primary contact info: %w", result.Error)
	}

	return model.ToEntity(), nil
}

// Update обновляет контактную информацию
func (r *ContactInfoRepositoryImpl) Update(ctx context.Context, contactInfo *entity.ContactInfo) error {
	model := &ContactInfoModel{}
	model.FromEntity(contactInfo)

	result := r.db.WithContext(ctx).Save(model)
	if result.Error != nil {
		return fmt.Errorf("failed to update contact info: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return repository.ErrContactInfoNotFound
	}

	return nil
}

// Delete удаляет контактную информацию
func (r *ContactInfoRepositoryImpl) Delete(ctx context.Context, id uuid.UUID) error {
	result := r.db.WithContext(ctx).Delete(&ContactInfoModel{}, "id = ?", id)
	if result.Error != nil {
		return fmt.Errorf("failed to delete contact info: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return repository.ErrContactInfoNotFound
	}

	return nil
}

// List получает список контактной информации с фильтрацией
func (r *ContactInfoRepositoryImpl) List(ctx context.Context, filter repository.ContactInfoFilter) ([]*entity.ContactInfo, error) {
	var models []ContactInfoModel
	query := r.db.WithContext(ctx)

	// Применение фильтров
	if filter.AccountID != uuid.Nil {
		query = query.Where("account_id = ?", filter.AccountID)
	}
	if filter.Type != "" {
		query = query.Where("type = ?", filter.Type)
	}
	if filter.IsPrimary != nil {
		query = query.Where("is_primary = ?", *filter.IsPrimary)
	}
	if filter.IsVerified != nil {
		query = query.Where("is_verified = ?", *filter.IsVerified)
	}
	if filter.Visibility != "" {
		query = query.Where("visibility = ?", filter.Visibility)
	}

	// Получение данных
	if err := query.Find(&models).Error; err != nil {
		return nil, fmt.Errorf("failed to list contact info: %w", err)
	}

	// Преобразование моделей в сущности
	contactInfos := make([]*entity.ContactInfo, len(models))
	for i, model := range models {
		contactInfos[i] = model.ToEntity()
	}

	return contactInfos, nil
}

// SetVerificationCode устанавливает код верификации для контактной информации
func (r *ContactInfoRepositoryImpl) SetVerificationCode(ctx context.Context, id uuid.UUID, code string, expires time.Time) error {
	result := r.db.WithContext(ctx).Model(&ContactInfoModel{}).Where("id = ?", id).Updates(map[string]interface{}{
		"verification_code":    code,
		"verification_expires": expires,
	})
	if result.Error != nil {
		return fmt.Errorf("failed to set verification code: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return repository.ErrContactInfoNotFound
	}

	return nil
}

// Verify верифицирует контактную информацию
func (r *ContactInfoRepositoryImpl) Verify(ctx context.Context, id uuid.UUID) error {
	result := r.db.WithContext(ctx).Model(&ContactInfoModel{}).Where("id = ?", id).Updates(map[string]interface{}{
		"is_verified":          true,
		"verification_code":    "",
		"verification_expires": nil,
	})
	if result.Error != nil {
		return fmt.Errorf("failed to verify contact info: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return repository.ErrContactInfoNotFound
	}

	return nil
}

// IncrementVerificationAttempts увеличивает счетчик попыток верификации
func (r *ContactInfoRepositoryImpl) IncrementVerificationAttempts(ctx context.Context, id uuid.UUID) error {
	result := r.db.WithContext(ctx).Exec("UPDATE contact_info SET verification_attempts = verification_attempts + 1 WHERE id = ?", id)
	if result.Error != nil {
		return fmt.Errorf("failed to increment verification attempts: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return repository.ErrContactInfoNotFound
	}

	return nil
}

// SetPrimary устанавливает контактную информацию как основную
func (r *ContactInfoRepositoryImpl) SetPrimary(ctx context.Context, id uuid.UUID) error {
	// Получаем текущую запись для определения типа и account_id
	var model ContactInfoModel
	if err := r.db.WithContext(ctx).First(&model, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return repository.ErrContactInfoNotFound
		}
		return fmt.Errorf("failed to get contact info: %w", err)
	}

	// Начинаем транзакцию
	tx := r.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return fmt.Errorf("failed to begin transaction: %w", tx.Error)
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Сбрасываем флаг is_primary для всех записей того же типа и account_id
	if err := tx.Model(&ContactInfoModel{}).Where("account_id = ? AND type = ? AND is_primary = ?", model.AccountID, model.Type, true).Update("is_primary", false).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to reset primary flag: %w", err)
	}

	// Устанавливаем флаг is_primary для текущей записи
	if err := tx.Model(&ContactInfoModel{}).Where("id = ?", id).Update("is_primary", true).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to set primary flag: %w", err)
	}

	// Коммитим транзакцию
	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// UnsetPrimaryByAccountIDAndType сбрасывает флаг основной контактной информации для всех записей определенного типа
func (r *ContactInfoRepositoryImpl) UnsetPrimaryByAccountIDAndType(ctx context.Context, accountID uuid.UUID, contactType entity.ContactType) error {
	result := r.db.WithContext(ctx).Model(&ContactInfoModel{}).Where("account_id = ? AND type = ? AND is_primary = ?", accountID, string(contactType), true).Update("is_primary", false)
	if result.Error != nil {
		return fmt.Errorf("failed to unset primary flag: %w", result.Error)
	}

	return nil
}
