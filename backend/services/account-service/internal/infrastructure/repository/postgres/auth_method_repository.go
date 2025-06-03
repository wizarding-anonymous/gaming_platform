// account-service/internal/infrastructure/repository/postgres/auth_method_repository.go
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

// AuthMethodModel представляет модель метода аутентификации в базе данных
type AuthMethodModel struct {
ID         uuid.UUID `gorm:"type:uuid;primary_key"`
AccountID  uuid.UUID `gorm:"type:uuid;index"`
Type       string    `gorm:"type:varchar(20);not null"`
Provider   string    `gorm:"type:varchar(50)"`
Identifier string    `gorm:"type:varchar(255)"`
Secret     string    `gorm:"type:varchar(255)"`
IsVerified bool      `gorm:"default:false"`
CreatedAt  time.Time
UpdatedAt  time.Time
DeletedAt  *time.Time `gorm:"index"`
}

// TableName возвращает имя таблицы
func (AuthMethodModel) TableName() string {
return "auth_methods"
}

// ToEntity преобразует модель в сущность
func (m *AuthMethodModel) ToEntity() *entity.AuthMethod {
return &entity.AuthMethod{
ID:         m.ID,
AccountID:  m.AccountID,
Type:       entity.AuthMethodType(m.Type),
Provider:   m.Provider,
Identifier: m.Identifier,
Secret:     m.Secret,
IsVerified: m.IsVerified,
CreatedAt:  m.CreatedAt,
UpdatedAt:  m.UpdatedAt,
}
}

// FromEntity преобразует сущность в модель
func (m *AuthMethodModel) FromEntity(authMethod *entity.AuthMethod) {
m.ID = authMethod.ID
m.AccountID = authMethod.AccountID
m.Type = string(authMethod.Type)
m.Provider = authMethod.Provider
m.Identifier = authMethod.Identifier
m.Secret = authMethod.Secret
m.IsVerified = authMethod.IsVerified
m.CreatedAt = authMethod.CreatedAt
m.UpdatedAt = authMethod.UpdatedAt
}

// AuthMethodRepositoryImpl реализация репозитория для работы с методами аутентификации
type AuthMethodRepositoryImpl struct {
db *gorm.DB
}

// NewAuthMethodRepository создает новый экземпляр репозитория для работы с методами аутентификации
func NewAuthMethodRepository(db *gorm.DB) repository.AuthMethodRepository {
return &AuthMethodRepositoryImpl{
db: db,
}
}

// Create создает новый метод аутентификации
func (r *AuthMethodRepositoryImpl) Create(ctx context.Context, authMethod *entity.AuthMethod) error {
model := &AuthMethodModel{}
model.FromEntity(authMethod)

result := r.db.WithContext(ctx).Create(model)
if result.Error != nil {
return fmt.Errorf("failed to create auth method: %w", result.Error)
}

return nil
}

// GetByID получает метод аутентификации по ID
func (r *AuthMethodRepositoryImpl) GetByID(ctx context.Context, id uuid.UUID) (*entity.AuthMethod, error) {
var model AuthMethodModel
result := r.db.WithContext(ctx).First(&model, "id = ?", id)
if result.Error != nil {
if errors.Is(result.Error, gorm.ErrRecordNotFound) {
return nil, repository.ErrAuthMethodNotFound
}
return nil, fmt.Errorf("failed to get auth method by ID: %w", result.Error)
}

return model.ToEntity(), nil
}

// GetByAccountID получает все методы аутентификации пользователя
func (r *AuthMethodRepositoryImpl) GetByAccountID(ctx context.Context, accountID uuid.UUID) ([]*entity.AuthMethod, error) {
var models []AuthMethodModel
result := r.db.WithContext(ctx).Where("account_id = ?", accountID).Find(&models)
if result.Error != nil {
return nil, fmt.Errorf("failed to get auth methods by account ID: %w", result.Error)
}

authMethods := make([]*entity.AuthMethod, len(models))
for i, model := range models {
authMethods[i] = model.ToEntity()
}

return authMethods, nil
}

// GetByTypeAndIdentifier получает метод аутентификации по типу и идентификатору
func (r *AuthMethodRepositoryImpl) GetByTypeAndIdentifier(ctx context.Context, authType entity.AuthMethodType, identifier string) (*entity.AuthMethod, error) {
var model AuthMethodModel
result := r.db.WithContext(ctx).First(&model, "type = ? AND identifier = ?", string(authType), identifier)
if result.Error != nil {
if errors.Is(result.Error, gorm.ErrRecordNotFound) {
return nil, repository.ErrAuthMethodNotFound
}
return nil, fmt.Errorf("failed to get auth method by type and identifier: %w", result.Error)
}

return model.ToEntity(), nil
}

// GetByProviderAndIdentifier получает метод аутентификации по провайдеру и идентификатору
func (r *AuthMethodRepositoryImpl) GetByProviderAndIdentifier(ctx context.Context, provider, identifier string) (*entity.AuthMethod, error) {
var model AuthMethodModel
result := r.db.WithContext(ctx).First(&model, "provider = ? AND identifier = ?", provider, identifier)
if result.Error != nil {
if errors.Is(result.Error, gorm.ErrRecordNotFound) {
return nil, repository.ErrAuthMethodNotFound
}
return nil, fmt.Errorf("failed to get auth method by provider and identifier: %w", result.Error)
}

return model.ToEntity(), nil
}

// Update обновляет метод аутентификации
func (r *AuthMethodRepositoryImpl) Update(ctx context.Context, authMethod *entity.AuthMethod) error {
model := &AuthMethodModel{}
model.FromEntity(authMethod)

result := r.db.WithContext(ctx).Save(model)
if result.Error != nil {
return fmt.Errorf("failed to update auth method: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrAuthMethodNotFound
}

return nil
}

// Delete удаляет метод аутентификации
func (r *AuthMethodRepositoryImpl) Delete(ctx context.Context, id uuid.UUID) error {
result := r.db.WithContext(ctx).Delete(&AuthMethodModel{}, "id = ?", id)
if result.Error != nil {
return fmt.Errorf("failed to delete auth method: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrAuthMethodNotFound
}

return nil
}

// DeleteByAccountID удаляет все методы аутентификации пользователя
func (r *AuthMethodRepositoryImpl) DeleteByAccountID(ctx context.Context, accountID uuid.UUID) error {
result := r.db.WithContext(ctx).Delete(&AuthMethodModel{}, "account_id = ?", accountID)
if result.Error != nil {
return fmt.Errorf("failed to delete auth methods by account ID: %w", result.Error)
}

return nil
}

// List получает список методов аутентификации с фильтрацией
func (r *AuthMethodRepositoryImpl) List(ctx context.Context, filter repository.AuthMethodFilter) ([]*entity.AuthMethod, error) {
var models []AuthMethodModel
query := r.db.WithContext(ctx)

// Применение фильтров
if filter.AccountID != uuid.Nil {
query = query.Where("account_id = ?", filter.AccountID)
}
if filter.Type != "" {
query = query.Where("type = ?", filter.Type)
}
if filter.Provider != "" {
query = query.Where("provider = ?", filter.Provider)
}
if filter.IsVerified != nil {
query = query.Where("is_verified = ?", *filter.IsVerified)
}

// Получение данных
if err := query.Find(&models).Error; err != nil {
return nil, fmt.Errorf("failed to list auth methods: %w", err)
}

// Преобразование моделей в сущности
authMethods := make([]*entity.AuthMethod, len(models))
for i, model := range models {
authMethods[i] = model.ToEntity()
}

return authMethods, nil
}

// Exists проверяет существование метода аутентификации по ID
func (r *AuthMethodRepositoryImpl) Exists(ctx context.Context, id uuid.UUID) (bool, error) {
var count int64
result := r.db.WithContext(ctx).Model(&AuthMethodModel{}).Where("id = ?", id).Count(&count)
if result.Error != nil {
return false, fmt.Errorf("failed to check auth method existence: %w", result.Error)
}

return count > 0, nil
}

// ExistsByTypeAndIdentifier проверяет существование метода аутентификации по типу и идентификатору
func (r *AuthMethodRepositoryImpl) ExistsByTypeAndIdentifier(ctx context.Context, authType entity.AuthMethodType, identifier string) (bool, error) {
var count int64
result := r.db.WithContext(ctx).Model(&AuthMethodModel{}).Where("type = ? AND identifier = ?", string(authType), identifier).Count(&count)
if result.Error != nil {
return false, fmt.Errorf("failed to check auth method existence by type and identifier: %w", result.Error)
}

return count > 0, nil
}

// UpdateSecret обновляет секрет метода аутентификации
func (r *AuthMethodRepositoryImpl) UpdateSecret(ctx context.Context, id uuid.UUID, secret string) error {
result := r.db.WithContext(ctx).Model(&AuthMethodModel{}).Where("id = ?", id).Update("secret", secret)
if result.Error != nil {
return fmt.Errorf("failed to update auth method secret: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrAuthMethodNotFound
}

return nil
}

// Verify верифицирует метод аутентификации
func (r *AuthMethodRepositoryImpl) Verify(ctx context.Context, id uuid.UUID) error {
result := r.db.WithContext(ctx).Model(&AuthMethodModel{}).Where("id = ?", id).Update("is_verified", true)
if result.Error != nil {
return fmt.Errorf("failed to verify auth method: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrAuthMethodNotFound
}

return nil
}
