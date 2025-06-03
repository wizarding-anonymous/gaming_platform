// account-service/internal/infrastructure/repository/postgres/profile_repository.go
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

// ProfileModel представляет модель профиля в базе данных
type ProfileModel struct {
ID          uuid.UUID `gorm:"type:uuid;primary_key"`
AccountID   uuid.UUID `gorm:"type:uuid;uniqueIndex"`
Nickname    string    `gorm:"type:varchar(50);uniqueIndex"`
RealName    string    `gorm:"type:varchar(100)"`
Bio         string    `gorm:"type:text"`
Location    string    `gorm:"type:varchar(100)"`
AvatarURL   string    `gorm:"type:varchar(255)"`
BannerURL   string    `gorm:"type:varchar(255)"`
Visibility  string    `gorm:"type:varchar(20);not null"`
DateOfBirth *time.Time
CreatedAt   time.Time
UpdatedAt   time.Time
}

// TableName возвращает имя таблицы
func (ProfileModel) TableName() string {
return "profiles"
}

// ToEntity преобразует модель в сущность
func (m *ProfileModel) ToEntity() *entity.Profile {
profile := &entity.Profile{
ID:         m.ID,
AccountID:  m.AccountID,
Nickname:   m.Nickname,
RealName:   m.RealName,
Bio:        m.Bio,
Location:   m.Location,
AvatarURL:  m.AvatarURL,
BannerURL:  m.BannerURL,
Visibility: entity.Visibility(m.Visibility),
CreatedAt:  m.CreatedAt,
UpdatedAt:  m.UpdatedAt,
}
if m.DateOfBirth != nil {
profile.DateOfBirth = *m.DateOfBirth
}
return profile
}

// FromEntity преобразует сущность в модель
func (m *ProfileModel) FromEntity(profile *entity.Profile) {
m.ID = profile.ID
m.AccountID = profile.AccountID
m.Nickname = profile.Nickname
m.RealName = profile.RealName
m.Bio = profile.Bio
m.Location = profile.Location
m.AvatarURL = profile.AvatarURL
m.BannerURL = profile.BannerURL
m.Visibility = string(profile.Visibility)
if !profile.DateOfBirth.IsZero() {
m.DateOfBirth = &profile.DateOfBirth
}
m.CreatedAt = profile.CreatedAt
m.UpdatedAt = profile.UpdatedAt
}

// ProfileRepositoryImpl реализация репозитория для работы с профилями
type ProfileRepositoryImpl struct {
db *gorm.DB
}

// NewProfileRepository создает новый экземпляр репозитория для работы с профилями
func NewProfileRepository(db *gorm.DB) repository.ProfileRepository {
return &ProfileRepositoryImpl{
db: db,
}
}

// Create создает новый профиль
func (r *ProfileRepositoryImpl) Create(ctx context.Context, profile *entity.Profile) error {
model := &ProfileModel{}
model.FromEntity(profile)

result := r.db.WithContext(ctx).Create(model)
if result.Error != nil {
return fmt.Errorf("failed to create profile: %w", result.Error)
}

return nil
}

// GetByID получает профиль по ID
func (r *ProfileRepositoryImpl) GetByID(ctx context.Context, id uuid.UUID) (*entity.Profile, error) {
var model ProfileModel
result := r.db.WithContext(ctx).First(&model, "id = ?", id)
if result.Error != nil {
if errors.Is(result.Error, gorm.ErrRecordNotFound) {
return nil, repository.ErrProfileNotFound
}
return nil, fmt.Errorf("failed to get profile by ID: %w", result.Error)
}

return model.ToEntity(), nil
}

// GetByAccountID получает профиль по ID аккаунта
func (r *ProfileRepositoryImpl) GetByAccountID(ctx context.Context, accountID uuid.UUID) (*entity.Profile, error) {
var model ProfileModel
result := r.db.WithContext(ctx).First(&model, "account_id = ?", accountID)
if result.Error != nil {
if errors.Is(result.Error, gorm.ErrRecordNotFound) {
return nil, repository.ErrProfileNotFound
}
return nil, fmt.Errorf("failed to get profile by account ID: %w", result.Error)
}

return model.ToEntity(), nil
}

// GetByNickname получает профиль по никнейму
func (r *ProfileRepositoryImpl) GetByNickname(ctx context.Context, nickname string) (*entity.Profile, error) {
var model ProfileModel
result := r.db.WithContext(ctx).First(&model, "nickname = ?", nickname)
if result.Error != nil {
if errors.Is(result.Error, gorm.ErrRecordNotFound) {
return nil, repository.ErrProfileNotFound
}
return nil, fmt.Errorf("failed to get profile by nickname: %w", result.Error)
}

return model.ToEntity(), nil
}

// Update обновляет профиль
func (r *ProfileRepositoryImpl) Update(ctx context.Context, profile *entity.Profile) error {
model := &ProfileModel{}
model.FromEntity(profile)

result := r.db.WithContext(ctx).Save(model)
if result.Error != nil {
return fmt.Errorf("failed to update profile: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrProfileNotFound
}

return nil
}

// Delete удаляет профиль
func (r *ProfileRepositoryImpl) Delete(ctx context.Context, id uuid.UUID) error {
result := r.db.WithContext(ctx).Delete(&ProfileModel{}, "id = ?", id)
if result.Error != nil {
return fmt.Errorf("failed to delete profile: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrProfileNotFound
}

return nil
}

// List получает список профилей с фильтрацией и пагинацией
func (r *ProfileRepositoryImpl) List(ctx context.Context, filter repository.ProfileFilter) ([]*entity.Profile, int64, error) {
var models []ProfileModel
var total int64

query := r.db.WithContext(ctx).Model(&ProfileModel{})

// Применение фильтров
if filter.Nickname != "" {
query = query.Where("nickname LIKE ?", "%"+filter.Nickname+"%")
}
if filter.RealName != "" {
query = query.Where("real_name LIKE ?", "%"+filter.RealName+"%")
}
if filter.Location != "" {
query = query.Where("location LIKE ?", "%"+filter.Location+"%")
}
if filter.Visibility != "" {
query = query.Where("visibility = ?", filter.Visibility)
}

// Подсчет общего количества записей
if err := query.Count(&total).Error; err != nil {
return nil, 0, fmt.Errorf("failed to count profiles: %w", err)
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
return nil, 0, fmt.Errorf("failed to list profiles: %w", err)
}

// Преобразование моделей в сущности
profiles := make([]*entity.Profile, len(models))
for i, model := range models {
profiles[i] = model.ToEntity()
}

return profiles, total, nil
}

// Exists проверяет существование профиля по ID
func (r *ProfileRepositoryImpl) Exists(ctx context.Context, id uuid.UUID) (bool, error) {
var count int64
result := r.db.WithContext(ctx).Model(&ProfileModel{}).Where("id = ?", id).Count(&count)
if result.Error != nil {
return false, fmt.Errorf("failed to check profile existence: %w", result.Error)
}

return count > 0, nil
}

// ExistsByAccountID проверяет существование профиля по ID аккаунта
func (r *ProfileRepositoryImpl) ExistsByAccountID(ctx context.Context, accountID uuid.UUID) (bool, error) {
var count int64
result := r.db.WithContext(ctx).Model(&ProfileModel{}).Where("account_id = ?", accountID).Count(&count)
if result.Error != nil {
return false, fmt.Errorf("failed to check profile existence by account ID: %w", result.Error)
}

return count > 0, nil
}

// ExistsByNickname проверяет существование профиля по никнейму
func (r *ProfileRepositoryImpl) ExistsByNickname(ctx context.Context, nickname string) (bool, error) {
var count int64
result := r.db.WithContext(ctx).Model(&ProfileModel{}).Where("nickname = ?", nickname).Count(&count)
if result.Error != nil {
return false, fmt.Errorf("failed to check profile existence by nickname: %w", result.Error)
}

return count > 0, nil
}

// UpdateNickname обновляет никнейм профиля
func (r *ProfileRepositoryImpl) UpdateNickname(ctx context.Context, id uuid.UUID, nickname string) error {
result := r.db.WithContext(ctx).Model(&ProfileModel{}).Where("id = ?", id).Update("nickname", nickname)
if result.Error != nil {
return fmt.Errorf("failed to update profile nickname: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrProfileNotFound
}

return nil
}

// UpdateVisibility обновляет видимость профиля
func (r *ProfileRepositoryImpl) UpdateVisibility(ctx context.Context, id uuid.UUID, visibility entity.Visibility) error {
result := r.db.WithContext(ctx).Model(&ProfileModel{}).Where("id = ?", id).Update("visibility", visibility)
if result.Error != nil {
return fmt.Errorf("failed to update profile visibility: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrProfileNotFound
}

return nil
}

// UpdateAvatarURL обновляет URL аватара профиля
func (r *ProfileRepositoryImpl) UpdateAvatarURL(ctx context.Context, id uuid.UUID, avatarURL string) error {
result := r.db.WithContext(ctx).Model(&ProfileModel{}).Where("id = ?", id).Update("avatar_url", avatarURL)
if result.Error != nil {
return fmt.Errorf("failed to update profile avatar URL: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrProfileNotFound
}

return nil
}

// UpdateBannerURL обновляет URL баннера профиля
func (r *ProfileRepositoryImpl) UpdateBannerURL(ctx context.Context, id uuid.UUID, bannerURL string) error {
result := r.db.WithContext(ctx).Model(&ProfileModel{}).Where("id = ?", id).Update("banner_url", bannerURL)
if result.Error != nil {
return fmt.Errorf("failed to update profile banner URL: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrProfileNotFound
}

return nil
}

// Anonymize анонимизирует данные профиля
func (r *ProfileRepositoryImpl) Anonymize(ctx context.Context, id uuid.UUID) error {
// Генерация анонимных данных
anonymousNickname := fmt.Sprintf("deleted_user_%s", uuid.New().String()[:8])

// Обновление данных профиля
result := r.db.WithContext(ctx).Model(&ProfileModel{}).Where("id = ?", id).Updates(map[string]interface{}{
"nickname":  anonymousNickname,
"real_name": "",
"bio":       "",
"location":  "",
})
if result.Error != nil {
return fmt.Errorf("failed to anonymize profile: %w", result.Error)
}

if result.RowsAffected == 0 {
return repository.ErrProfileNotFound
}

return nil
}
