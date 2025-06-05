// File: backend/services/account-service/internal/app/usecase/profile_usecase.go
// account-service\internal\app\usecase\profile_usecase.go

package usecase

import (
	"context"
	"io"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/gaiming/account-service/internal/domain/entity"
	"github.com/gaiming/account-service/internal/domain/errors"
)

// ProfileRepository интерфейс для работы с репозиторием профилей
type ProfileRepository interface {
	Create(ctx context.Context, profile *entity.Profile) error
	GetByID(ctx context.Context, id string) (*entity.Profile, error)
	GetByAccountID(ctx context.Context, accountID string) (*entity.Profile, error)
	GetByAccountIDs(ctx context.Context, accountIDs []string) ([]*entity.Profile, error)
	Update(ctx context.Context, profile *entity.Profile) error
	Delete(ctx context.Context, id string) error
}

// AvatarRepository интерфейс для работы с репозиторием аватаров
type AvatarRepository interface {
	Create(ctx context.Context, avatar *entity.Avatar) error
	GetByID(ctx context.Context, id string) (*entity.Avatar, error)
	GetByAccountID(ctx context.Context, accountID string) ([]*entity.Avatar, error)
	GetCurrentByAccountID(ctx context.Context, accountID string) (*entity.Avatar, error)
	Update(ctx context.Context, avatar *entity.Avatar) error
	Delete(ctx context.Context, id string) error
	SetCurrent(ctx context.Context, id string, accountID string) error
}

// ProfileHistoryRepository интерфейс для работы с репозиторием истории профилей
type ProfileHistoryRepository interface {
	Create(ctx context.Context, entry *entity.ProfileHistoryEntry) error
	GetByProfileID(ctx context.Context, profileID string, page, pageSize int) ([]*entity.ProfileHistoryEntry, int, error)
}

// ProfileCache интерфейс для работы с кэшем профилей
type ProfileCache interface {
	Set(ctx context.Context, profile *entity.Profile, ttl time.Duration) error
	Get(ctx context.Context, accountID string) (*entity.Profile, error)
	Delete(ctx context.Context, accountID string) error
}

// ProfileEventProducer интерфейс для отправки событий профиля
type ProfileEventProducer interface {
	PublishProfileCreated(ctx context.Context, profile *entity.Profile) error
	PublishProfileUpdated(ctx context.Context, profile *entity.Profile) error
	PublishAvatarUploaded(ctx context.Context, avatar *entity.Avatar) error
}

// ProfileUseCase реализует бизнес-логику для работы с профилями
type ProfileUseCase struct {
	profileRepo        ProfileRepository
	accountRepo        AccountRepository
	avatarRepo         AvatarRepository
	profileHistoryRepo ProfileHistoryRepository
	cache              ProfileCache
	eventProducer      ProfileEventProducer
	logger             *zap.SugaredLogger
}

// NewProfileUseCase создает новый экземпляр ProfileUseCase
func NewProfileUseCase(
	profileRepo ProfileRepository,
	accountRepo AccountRepository,
	avatarRepo AvatarRepository,
	profileHistoryRepo ProfileHistoryRepository,
	cache ProfileCache,
	eventProducer ProfileEventProducer,
	logger *zap.SugaredLogger,
) *ProfileUseCase {
	return &ProfileUseCase{
		profileRepo:        profileRepo,
		accountRepo:        accountRepo,
		avatarRepo:         avatarRepo,
		profileHistoryRepo: profileHistoryRepo,
		cache:              cache,
		eventProducer:      eventProducer,
		logger:             logger,
	}
}

// GetProfileByAccountID получает профиль по ID аккаунта
func (uc *ProfileUseCase) GetProfileByAccountID(ctx context.Context, accountID string) (*entity.Profile, error) {
	// Проверяем существование аккаунта
	_, err := uc.accountRepo.GetByID(ctx, accountID)
	if err != nil {
		if err == errors.ErrAccountNotFound {
			return nil, errors.ErrAccountNotFound
		}
		uc.logger.Errorw("Failed to get account", "error", err)
		return nil, errors.ErrInternalServerError
	}

	// Пытаемся получить профиль из кэша
	profile, err := uc.cache.Get(ctx, accountID)
	if err == nil {
		return profile, nil
	}

	// Если профиль не найден в кэше, получаем из БД
	profile, err = uc.profileRepo.GetByAccountID(ctx, accountID)
	if err != nil {
		if err == errors.ErrProfileNotFound {
			return nil, errors.ErrProfileNotFound
		}
		uc.logger.Errorw("Failed to get profile by account ID", "error", err)
		return nil, errors.ErrInternalServerError
	}

	// Сохраняем профиль в кэш
	if err := uc.cache.Set(ctx, profile, 30*time.Minute); err != nil {
		uc.logger.Errorw("Failed to cache profile", "error", err)
		// Не возвращаем ошибку, так как это некритично
	}

	return profile, nil
}

// GetProfiles получает профили по списку ID аккаунтов
func (uc *ProfileUseCase) GetProfiles(ctx context.Context, accountIDs []string) ([]*entity.Profile, error) {
	profiles, err := uc.profileRepo.GetByAccountIDs(ctx, accountIDs)
	if err != nil {
		uc.logger.Errorw("Failed to get profiles by account IDs", "error", err)
		return nil, errors.ErrInternalServerError
	}

	// Кэшируем полученные профили
	for _, profile := range profiles {
		if err := uc.cache.Set(ctx, profile, 30*time.Minute); err != nil {
			uc.logger.Errorw("Failed to cache profile", "error", err)
			// Не возвращаем ошибку, так как это некритично
		}
	}

	return profiles, nil
}

// UpdateProfile обновляет профиль пользователя
func (uc *ProfileUseCase) UpdateProfile(
	ctx context.Context,
	accountID string,
	nickname string,
	bio string,
	country string,
	city string,
	birthDate string,
	gender string,
	visibility string,
	changedByAccountID string,
) (*entity.Profile, error) {
	// Проверяем существование аккаунта
	_, err := uc.accountRepo.GetByID(ctx, accountID)
	if err != nil {
		if err == errors.ErrAccountNotFound {
			return nil, errors.ErrAccountNotFound
		}
		uc.logger.Errorw("Failed to get account", "error", err)
		return nil, errors.ErrInternalServerError
	}

	// Получаем текущий профиль
	profile, err := uc.profileRepo.GetByAccountID(ctx, accountID)
	if err != nil {
		if err == errors.ErrProfileNotFound {
			// Если профиль не найден, создаем новый
			profile = entity.NewProfile(accountID, nickname)
			profile.ID = uuid.New().String()
			if err := uc.profileRepo.Create(ctx, profile); err != nil {
				uc.logger.Errorw("Failed to create profile", "error", err)
				return nil, errors.ErrInternalServerError
			}
		} else {
			uc.logger.Errorw("Failed to get profile by account ID", "error", err)
			return nil, errors.ErrInternalServerError
		}
	}

	// Сохраняем старые значения для истории
	oldNickname := profile.Nickname
	oldBio := profile.Bio
	oldCountry := profile.Country
	oldCity := profile.City
	oldBirthDate := profile.BirthDate
	oldGender := profile.Gender
	oldVisibility := string(profile.Visibility)

	// Обновляем профиль
	profileVisibility := entity.ProfileVisibility(visibility)
	if visibility != "" && profileVisibility != entity.ProfileVisibilityPublic && 
	   profileVisibility != entity.ProfileVisibilityFriends && 
	   profileVisibility != entity.ProfileVisibilityPrivate {
		return nil, errors.ErrInvalidProfileData
	}

	profile.UpdateProfile(nickname, bio, country, city, birthDate, gender, profileVisibility)

	// Сохраняем изменения в БД
	if err := uc.profileRepo.Update(ctx, profile); err != nil {
		uc.logger.Errorw("Failed to update profile", "error", err)
		return nil, errors.ErrInternalServerError
	}

	// Записываем историю изменений
	if nickname != "" && nickname != oldNickname {
		entry := entity.NewProfileHistoryEntry(profile.ID, "nickname", oldNickname, nickname, changedByAccountID)
		entry.ID = uuid.New().String()
		if err := uc.profileHistoryRepo.Create(ctx, entry); err != nil {
			uc.logger.Errorw("Failed to create profile history entry", "error", err)
			// Не возвращаем ошибку, так как это некритично
		}
	}

	if bio != "" && bio != oldBio {
		entry := entity.NewProfileHistoryEntry(profile.ID, "bio", oldBio, bio, changedByAccountID)
		entry.ID = uuid.New().String()
		if err := uc.profileHistoryRepo.Create(ctx, entry); err != nil {
			uc.logger.Errorw("Failed to create profile history entry", "error", err)
			// Не возвращаем ошибку, так как это некритично
		}
	}

	if country != "" && country != oldCountry {
		entry := entity.NewProfileHistoryEntry(profile.ID, "country", oldCountry, country, changedByAccountID)
		entry.ID = uuid.New().String()
		if err := uc.profileHistoryRepo.Create(ctx, entry); err != nil {
			uc.logger.Errorw("Failed to create profile history entry", "error", err)
			// Не возвращаем ошибку, так как это некритично
		}
	}

	if city != "" && city != oldCity {
		entry := entity.NewProfileHistoryEntry(profile.ID, "city", oldCity, city, changedByAccountID)
		entry.ID = uuid.New().String()
		if err := uc.profileHistoryRepo.Create(ctx, entry); err != nil {
			uc.logger.Errorw("Failed to create profile history entry", "error", err)
			// Не возвращаем ошибку, так как это некритично
		}
	}

	if birthDate != "" && birthDate != oldBirthDate {
		entry := entity.NewProfileHistoryEntry(profile.ID, "birth_date", oldBirthDate, birthDate, changedByAccountID)
		entry.ID = uuid.New().String()
		if err := uc.profileHistoryRepo.Create(ctx, entry); err != nil {
			uc.logger.Errorw("Failed to create profile history entry", "error", err)
			// Не возвращаем ошибку, так как это некритично
		}
	}

	if gender != "" && gender != oldGender {
		entry := entity.NewProfileHistoryEntry(profile.ID, "gender", oldGender, gender, changedByAccountID)
		entry.ID = uuid.New().String()
		if err := uc.profileHistoryRepo.Create(ctx, entry); err != nil {
			uc.logger.Errorw("Failed to create profile history entry", "error", err)
			// Не возвращаем ошибку, так как это некритично
		}
	}

	if visibility != "" && visibility != oldVisibility {
		entry := entity.NewProfileHistoryEntry(profile.ID, "visibility", oldVisibility, visibility, changedByAccountID)
		entry.ID = uuid.New().String()
		if err := uc.profileHistoryRepo.Create(ctx, entry); err != nil {
			uc.logger.Errorw("Failed to create profile history entry", "error", err)
			// Не возвращаем ошибку, так как это некритично
		}
	}

	// Обновляем кэш
	if err := uc.cache.Set(ctx, profile, 30*time.Minute); err != nil {
		uc.logger.Errorw("Failed to update profile in cache", "error", err)
		// Не возвращаем ошибку, так как это некритично
	}

	// Публикуем событие об обновлении профиля
	if err := uc.eventProducer.PublishProfileUpdated(ctx, profile); err != nil {
		uc.logger.Errorw("Failed to publish profile updated event", "error", err)
		// Не возвращаем ошибку, так как это некритично
	}

	return profile, nil
}

// UploadAvatar загружает аватар пользователя
func (uc *ProfileUseCase) UploadAvatar(ctx context.Context, accountID string, imageData io.Reader, filename string, size int64) (*entity.Avatar, error) {
	// Проверяем существование аккаунта
	_, err := uc.accountRepo.GetByID(ctx, accountID)
	if err != nil {
		if err == errors.ErrAccountNotFound {
			return nil, errors.ErrAccountNotFound
		}
		uc.logger.Errorw("Failed to get account", "error", err)
		return nil, errors.ErrInternalServerError
	}

	// Проверяем размер изображения
	if size > 5*1024*1024 { // 5 MB
		return nil, errors.ErrImageTooLarge
	}

	// Здесь должна быть логика загрузки изображения в хранилище и получения URL
	// В реальном приложении это может быть загрузка в S3, CDN и т.д.
	// Для примера просто генерируем URL
	avatarURL := "https://storage.example.com/avatars/" + accountID + "/" + uuid.New().String() + ".jpg"

	// Создаем новый аватар
	avatar := entity.NewAvatar(accountID, avatarURL, true)
	avatar.ID = uuid.New().String()

	// Сохраняем аватар в БД
	if err := uc.avatarRepo.Create(ctx, avatar); err != nil {
		uc.logger.Errorw("Failed to create avatar", "error", err)
		return nil, errors.ErrInternalServerError
	}

	// Устанавливаем новый аватар как текущий
	if err := uc.avatarRepo.SetCurrent(ctx, avatar.ID, accountID); err != nil {
		uc.logger.Errorw("Failed to set avatar as current", "error", err)
		// Не возвращаем ошибку, так как аватар уже создан
	}

	// Обновляем URL аватара в профиле
	profile, err := uc.profileRepo.GetByAccountID(ctx, accountID)
	if err == nil {
		profile.SetAvatar(avatarURL)
		if err := uc.profileRepo.Update(ctx, profile); err != nil {
			uc.logger.Errorw("Failed to update profile with avatar URL", "error", err)
			// Не возвращаем ошибку, так как аватар уже создан
		}

		// Обновляем кэш
		if err := uc.cache.Set(ctx, profile, 30*time.Minute); err != nil {
			uc.logger.Errorw("Failed to update profile in cache", "error", err)
			// Не возвращаем ошибку, так как это некритично
		}
	}

	// Публикуем событие о загрузке аватара
	if err := uc.eventProducer.PublishAvatarUploaded(ctx, avatar); err != nil {
		uc.logger.Errorw("Failed to publish avatar uploaded event", "error", err)
		// Не возвращаем ошибку, так как это некритично
	}

	return avatar, nil
}

// GetProfileHistory получает историю изменений профиля
func (uc *ProfileUseCase) GetProfileHistory(ctx context.Context, accountID string, page, pageSize int) ([]*entity.ProfileHistoryEntry, int, error) {
	// Проверяем существование аккаунта
	_, err := uc.accountRepo.GetByID(ctx, accountID)
	if err != nil {
		if err == errors.ErrAccountNotFound {
			return nil, 0, errors.ErrAccountNotFound
		}
		uc.logger.Errorw("Failed to get account", "error", err)
		return nil, 0, errors.ErrInternalServerError
	}

	// Получаем профиль
	profile, err := uc.profileRepo.GetByAccountID(ctx, accountID)
	if err != nil {
		if err == errors.ErrProfileNotFound {
			return nil, 0, errors.ErrProfileNotFound
		}
		uc.logger.Errorw("Failed to get profile by account ID", "error", err)
		return nil, 0, errors.ErrInternalServerError
	}

	// Получаем историю изменений
	history, total, err := uc.profileHistoryRepo.GetByProfileID(ctx, profile.ID, page, pageSize)
	if err != nil {
		uc.logger.Errorw("Failed to get profile history", "error", err)
		return nil, 0, errors.ErrInternalServerError
	}

	return history, total, nil
}
