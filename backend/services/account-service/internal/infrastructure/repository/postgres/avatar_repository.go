// File: backend/services/account-service/internal/infrastructure/repository/postgres/avatar_repository.go
// account-service/internal/infrastructure/repository/postgres/avatar_repository.go
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/steamru/account-service/internal/domain/entity"
	"github.com/steamru/account-service/internal/domain/repository"
)

// AvatarModel представляет модель аватара в базе данных
type AvatarModel struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key"`
	AccountID uuid.UUID `gorm:"type:uuid;index"`
	Type      string    `gorm:"type:varchar(20);not null"`
	URL       string    `gorm:"type:varchar(255);not null"`
	Filename  string    `gorm:"type:varchar(255);not null"`
	Size      int64     `gorm:"not null"`
	MimeType  string    `gorm:"type:varchar(100);not null"`
	Width     int       `gorm:"not null"`
	Height    int       `gorm:"not null"`
	IsActive  bool      `gorm:"default:false"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// TableName возвращает имя таблицы
func (AvatarModel) TableName() string {
	return "avatars"
}

// ToEntity преобразует модель в сущность
func (m *AvatarModel) ToEntity() *entity.Avatar {
	return &entity.Avatar{
		ID:        m.ID,
		AccountID: m.AccountID,
		Type:      entity.AvatarType(m.Type),
		URL:       m.URL,
		Filename:  m.Filename,
		Size:      m.Size,
		MimeType:  m.MimeType,
		Width:     m.Width,
		Height:    m.Height,
		IsActive:  m.IsActive,
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.UpdatedAt,
	}
}

// FromEntity преобразует сущность в модель
func (m *AvatarModel) FromEntity(avatar *entity.Avatar) {
	m.ID = avatar.ID
	m.AccountID = avatar.AccountID
	m.Type = string(avatar.Type)
	m.URL = avatar.URL
	m.Filename = avatar.Filename
	m.Size = avatar.Size
	m.MimeType = avatar.MimeType
	m.Width = avatar.Width
	m.Height = avatar.Height
	m.IsActive = avatar.IsActive
	m.CreatedAt = avatar.CreatedAt
	m.UpdatedAt = avatar.UpdatedAt
}

// AvatarRepositoryImpl реализация репозитория для работы с аватарами
type AvatarRepositoryImpl struct {
	db *gorm.DB
}

// NewAvatarRepository создает новый экземпляр репозитория для работы с аватарами
func NewAvatarRepository(db *gorm.DB) repository.AvatarRepository {
	return &AvatarRepositoryImpl{
		db: db,
	}
}

// Create создает новый аватар
func (r *AvatarRepositoryImpl) Create(ctx context.Context, avatar *entity.Avatar) error {
	model := &AvatarModel{}
	model.FromEntity(avatar)

	result := r.db.WithContext(ctx).Create(model)
	if result.Error != nil {
		return fmt.Errorf("failed to create avatar: %w", result.Error)
	}

	return nil
}

// GetByID получает аватар по ID
func (r *AvatarRepositoryImpl) GetByID(ctx context.Context, id uuid.UUID) (*entity.Avatar, error) {
	var model AvatarModel
	result := r.db.WithContext(ctx).First(&model, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, repository.ErrAvatarNotFound
		}
		return nil, fmt.Errorf("failed to get avatar by ID: %w", result.Error)
	}

	return model.ToEntity(), nil
}

// GetByAccountID получает все аватары пользователя
func (r *AvatarRepositoryImpl) GetByAccountID(ctx context.Context, accountID uuid.UUID) ([]*entity.Avatar, error) {
	var models []AvatarModel
	result := r.db.WithContext(ctx).Where("account_id = ?", accountID).Find(&models)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to get avatars by account ID: %w", result.Error)
	}

	avatars := make([]*entity.Avatar, len(models))
	for i, model := range models {
		avatars[i] = model.ToEntity()
	}

	return avatars, nil
}

// GetActiveByAccountIDAndType получает активный аватар определенного типа
func (r *AvatarRepositoryImpl) GetActiveByAccountIDAndType(ctx context.Context, accountID uuid.UUID, avatarType entity.AvatarType) (*entity.Avatar, error) {
	var model AvatarModel
	result := r.db.WithContext(ctx).First(&model, "account_id = ? AND type = ? AND is_active = ?", accountID, string(avatarType), true)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, repository.ErrAvatarNotFound
		}
		return nil, fmt.Errorf("failed to get active avatar: %w", result.Error)
	}

	return model.ToEntity(), nil
}

// Update обновляет аватар
func (r *AvatarRepositoryImpl) Update(ctx context.Context, avatar *entity.Avatar) error {
	model := &AvatarModel{}
	model.FromEntity(avatar)

	result := r.db.WithContext(ctx).Save(model)
	if result.Error != nil {
		return fmt.Errorf("failed to update avatar: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return repository.ErrAvatarNotFound
	}

	return nil
}

// Delete удаляет аватар
func (r *AvatarRepositoryImpl) Delete(ctx context.Context, id uuid.UUID) error {
	result := r.db.WithContext(ctx).Delete(&AvatarModel{}, "id = ?", id)
	if result.Error != nil {
		return fmt.Errorf("failed to delete avatar: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return repository.ErrAvatarNotFound
	}

	return nil
}

// List получает список аватаров с фильтрацией
func (r *AvatarRepositoryImpl) List(ctx context.Context, filter repository.AvatarFilter) ([]*entity.Avatar, error) {
	var models []AvatarModel
	query := r.db.WithContext(ctx)

	// Применение фильтров
	if filter.AccountID != uuid.Nil {
		query = query.Where("account_id = ?", filter.AccountID)
	}
	if filter.Type != "" {
		query = query.Where("type = ?", filter.Type)
	}
	if filter.IsActive != nil {
		query = query.Where("is_active = ?", *filter.IsActive)
	}

	// Получение данных
	if err := query.Find(&models).Error; err != nil {
		return nil, fmt.Errorf("failed to list avatars: %w", err)
	}

	// Преобразование моделей в сущности
	avatars := make([]*entity.Avatar, len(models))
	for i, model := range models {
		avatars[i] = model.ToEntity()
	}

	return avatars, nil
}

// Activate активирует аватар
func (r *AvatarRepositoryImpl) Activate(ctx context.Context, id uuid.UUID) error {
	// Получаем текущую запись для определения типа и account_id
	var model AvatarModel
	if err := r.db.WithContext(ctx).First(&model, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return repository.ErrAvatarNotFound
		}
		return fmt.Errorf("failed to get avatar: %w", err)
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

	// Деактивируем все аватары того же типа и account_id
	if err := tx.Model(&AvatarModel{}).Where("account_id = ? AND type = ? AND is_active = ?", model.AccountID, model.Type, true).Update("is_active", false).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to deactivate avatars: %w", err)
	}

	// Активируем текущий аватар
	if err := tx.Model(&AvatarModel{}).Where("id = ?", id).Update("is_active", true).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to activate avatar: %w", err)
	}

	// Коммитим транзакцию
	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// Deactivate деактивирует аватар
func (r *AvatarRepositoryImpl) Deactivate(ctx context.Context, id uuid.UUID) error {
	result := r.db.WithContext(ctx).Model(&AvatarModel{}).Where("id = ?", id).Update("is_active", false)
	if result.Error != nil {
		return fmt.Errorf("failed to deactivate avatar: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return repository.ErrAvatarNotFound
	}

	return nil
}

// DeactivateAllByAccountIDAndType деактивирует все аватары определенного типа
func (r *AvatarRepositoryImpl) DeactivateAllByAccountIDAndType(ctx context.Context, accountID uuid.UUID, avatarType entity.AvatarType) error {
	result := r.db.WithContext(ctx).Model(&AvatarModel{}).Where("account_id = ? AND type = ? AND is_active = ?", accountID, string(avatarType), true).Update("is_active", false)
	if result.Error != nil {
		return fmt.Errorf("failed to deactivate avatars: %w", result.Error)
	}

	return nil
}

// UpdateURL обновляет URL аватара
func (r *AvatarRepositoryImpl) UpdateURL(ctx context.Context, id uuid.UUID, url string) error {
	result := r.db.WithContext(ctx).Model(&AvatarModel{}).Where("id = ?", id).Update("url", url)
	if result.Error != nil {
		return fmt.Errorf("failed to update avatar URL: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return repository.ErrAvatarNotFound
	}

	return nil
}
