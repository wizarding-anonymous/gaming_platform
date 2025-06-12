// File: backend/services/account-service/internal/infrastructure/repository/postgres/account_repository.go
// account-service/internal/infrastructure/repository/postgres/account_repository.go
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

// AccountModel представляет модель аккаунта в базе данных
type AccountModel struct {
ID        uuid.UUID `gorm:"type:uuid;primary_key"`
Username  string    `gorm:"type:varchar(50);uniqueIndex"`
Email     string    `gorm:"type:varchar(255);uniqueIndex"`
Role      string    `gorm:"type:varchar(20);not null"`
Status    string    `gorm:"type:varchar(20);not null"`
CreatedAt time.Time
UpdatedAt time.Time
DeletedAt *time.Time `gorm:"index"`
}

// TableName возвращает имя таблицы
func (AccountModel) TableName() string {
return "accounts"
}

// ToEntity преобразует модель в сущность
func (m *AccountModel) ToEntity() *entity.Account {
account := &entity.Account{
ID:        m.ID,
Username:  m.Username,
Email:     m.Email,
Role:      entity.Role(m.Role),
Status:    entity.Status(m.Status),
CreatedAt: m.CreatedAt,
UpdatedAt: m.UpdatedAt,
}
if m.DeletedAt != nil {
account.DeletedAt = *m.DeletedAt
}
return account
}

// FromEntity преобразует сущность в модель
func (m *AccountModel) FromEntity(account *entity.Account) {
m.ID = account.ID
m.Username = account.Username
m.Email = account.Email
m.Role = string(account.Role)
m.Status = string(account.Status)
m.CreatedAt = account.CreatedAt
m.UpdatedAt = account.UpdatedAt
if !account.DeletedAt.IsZero() {
m.DeletedAt = &account.DeletedAt
}
}

// AccountRepositoryImpl реализация репозитория для работы с аккаунтами
type AccountRepositoryImpl struct {
db *gorm.DB
}

// NewAccountRepository создает новый экземпляр репозитория для работы с аккаунтами
func NewAccountRepository(db *gorm.DB) repository.AccountRepository {
return &AccountRepositoryImpl{
db: db,
}
}

// Create создает новый аккаунт
func (r *AccountRepositoryImpl) Create(ctx context.Context, account *entity.Account) error {
model := &AccountModel{}
model.FromEntity(account)

result := r.db.WithContext(ctx).Create(model)
if result.Error != nil {
return fmt.Errorf("failed to create account: %w", result.Error)
}

return nil
}

// GetByID получает аккаунт по ID
func (r *AccountRepositoryImpl) GetByID(ctx context.Context, id uuid.UUID) (*entity.Account, error) {
var model AccountModel
result := r.db.WithContext(ctx).First(&model, "id = ?", id)
if result.Error != nil {
if errors.Is(result.Error, gorm.ErrRecordNotFound) {
return nil, repository.ErrAccountNotFound
}
return nil, fmt.Errorf("failed to get account by ID: %w", result.Error)
}

return model.ToEntity(), nil
}

// GetByUsername получает аккаунт по имени пользователя
func (r *AccountRepositoryImpl) GetByUsername(ctx context.Context, username string) (*entity.Account, error) {
var model AccountModel
result := r.db.WithContext(ctx).First(&model, "username = ?", username)
if result.Error != nil {
if errors.Is(result.Error, gorm.ErrRecordNotFound) {
return nil, repository.ErrAccountNotFound
}
return nil, fmt.Errorf("failed to get account by username: %w", result.Error)
}

return model.ToEntity(), nil
}

// GetByEmail получает аккаунт по email
func (r *AccountRepositoryImpl) GetByEmail(ctx context.Context, email string) (*entity.Account, error) {
var model AccountModel
result := r.db.WithContext(ctx).First(&model, "email = ?", email)
if result.Error != nil {
if errors.Is(result.Error, gorm.ErrRecordNotFound) {
return nil, repository.ErrAccountNotFound
}
return nil, fmt.Errorf("failed to get account by email: %w", result.Error)
}

return model.ToEntity(), nil
}

// Update обновляет аккаунт
func (r *AccountRepositoryImpl) Update(ctx context.Context, account *entity.Account) error {
model := &AccountModel{}
model.FromEntity(account)

result := r.db.WithContext(ctx).Save(model)
if result.Error != nil {
return fmt.Errorf("failed to update account: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrAccountNotFound
}

return nil
}

// Delete удаляет аккаунт (soft delete)
func (r *AccountRepositoryImpl) Delete(ctx context.Context, id uuid.UUID) error {
result := r.db.WithContext(ctx).Delete(&AccountModel{}, "id = ?", id)
if result.Error != nil {
return fmt.Errorf("failed to delete account: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrAccountNotFound
}

return nil
}

// HardDelete полностью удаляет аккаунт из базы данных
func (r *AccountRepositoryImpl) HardDelete(ctx context.Context, id uuid.UUID) error {
result := r.db.WithContext(ctx).Unscoped().Delete(&AccountModel{}, "id = ?", id)
if result.Error != nil {
return fmt.Errorf("failed to hard delete account: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrAccountNotFound
}

return nil
}

// List получает список аккаунтов с фильтрацией и пагинацией
func (r *AccountRepositoryImpl) List(ctx context.Context, filter repository.AccountFilter) ([]*entity.Account, int64, error) {
var models []AccountModel
var total int64

query := r.db.WithContext(ctx).Model(&AccountModel{})

// Применение фильтров
if filter.Username != "" {
query = query.Where("username LIKE ?", "%"+filter.Username+"%")
}
if filter.Email != "" {
query = query.Where("email LIKE ?", "%"+filter.Email+"%")
}
if filter.Role != "" {
query = query.Where("role = ?", filter.Role)
}
if filter.Status != "" {
query = query.Where("status = ?", filter.Status)
}
if filter.CreatedAfter != nil {
query = query.Where("created_at >= ?", filter.CreatedAfter)
}
if filter.CreatedBefore != nil {
query = query.Where("created_at <= ?", filter.CreatedBefore)
}

// Подсчет общего количества записей
if err := query.Count(&total).Error; err != nil {
return nil, 0, fmt.Errorf("failed to count accounts: %w", err)
}

// Применение пагинации
if filter.Limit > 0 {
query = query.Limit(filter.Limit)
}
if filter.Offset > 0 {
query = query.Offset(filter.Offset)
}

// Применение сортировки
if filter.SortBy != "" {
direction := "ASC"
if filter.SortDesc {
direction = "DESC"
}
query = query.Order(fmt.Sprintf("%s %s", filter.SortBy, direction))
} else {
query = query.Order("created_at DESC")
}

// Получение данных
if err := query.Find(&models).Error; err != nil {
return nil, 0, fmt.Errorf("failed to list accounts: %w", err)
}

// Преобразование моделей в сущности
accounts := make([]*entity.Account, len(models))
for i, model := range models {
accounts[i] = model.ToEntity()
}

return accounts, total, nil
}

// Exists проверяет существование аккаунта по ID
func (r *AccountRepositoryImpl) Exists(ctx context.Context, id uuid.UUID) (bool, error) {
var count int64
result := r.db.WithContext(ctx).Model(&AccountModel{}).Where("id = ?", id).Count(&count)
if result.Error != nil {
return false, fmt.Errorf("failed to check account existence: %w", result.Error)
}

return count > 0, nil
}

// ExistsByUsername проверяет существование аккаунта по имени пользователя
func (r *AccountRepositoryImpl) ExistsByUsername(ctx context.Context, username string) (bool, error) {
var count int64
result := r.db.WithContext(ctx).Model(&AccountModel{}).Where("username = ?", username).Count(&count)
if result.Error != nil {
return false, fmt.Errorf("failed to check account existence by username: %w", result.Error)
}

return count > 0, nil
}

// ExistsByEmail проверяет существование аккаунта по email
func (r *AccountRepositoryImpl) ExistsByEmail(ctx context.Context, email string) (bool, error) {
var count int64
result := r.db.WithContext(ctx).Model(&AccountModel{}).Where("email = ?", email).Count(&count)
if result.Error != nil {
return false, fmt.Errorf("failed to check account existence by email: %w", result.Error)
}

return count > 0, nil
}

// UpdateStatus обновляет статус аккаунта
func (r *AccountRepositoryImpl) UpdateStatus(ctx context.Context, id uuid.UUID, status entity.Status) error {
result := r.db.WithContext(ctx).Model(&AccountModel{}).Where("id = ?", id).Update("status", status)
if result.Error != nil {
return fmt.Errorf("failed to update account status: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrAccountNotFound
}

return nil
}

// UpdateRole обновляет роль аккаунта
func (r *AccountRepositoryImpl) UpdateRole(ctx context.Context, id uuid.UUID, role entity.Role) error {
result := r.db.WithContext(ctx).Model(&AccountModel{}).Where("id = ?", id).Update("role", role)
if result.Error != nil {
return fmt.Errorf("failed to update account role: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrAccountNotFound
}

return nil
}

// UpdateEmail обновляет email аккаунта
func (r *AccountRepositoryImpl) UpdateEmail(ctx context.Context, id uuid.UUID, email string) error {
result := r.db.WithContext(ctx).Model(&AccountModel{}).Where("id = ?", id).Update("email", email)
if result.Error != nil {
return fmt.Errorf("failed to update account email: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrAccountNotFound
}

return nil
}

// UpdateUsername обновляет имя пользователя аккаунта
func (r *AccountRepositoryImpl) UpdateUsername(ctx context.Context, id uuid.UUID, username string) error {
result := r.db.WithContext(ctx).Model(&AccountModel{}).Where("id = ?", id).Update("username", username)
if result.Error != nil {
return fmt.Errorf("failed to update account username: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrAccountNotFound
}

return nil
}

// Anonymize анонимизирует данные аккаунта
func (r *AccountRepositoryImpl) Anonymize(ctx context.Context, id uuid.UUID) error {
// Генерация анонимных данных
anonymousUsername := fmt.Sprintf("deleted_user_%s", uuid.New().String()[:8])
anonymousEmail := fmt.Sprintf("deleted_%s@example.com", uuid.New().String()[:8])

// Обновление данных аккаунта
result := r.db.WithContext(ctx).Model(&AccountModel{}).Where("id = ?", id).Updates(map[string]interface{}{
"username": anonymousUsername,
"email":    anonymousEmail,
})
if result.Error != nil {
return fmt.Errorf("failed to anonymize account: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrAccountNotFound
}

return nil
}
