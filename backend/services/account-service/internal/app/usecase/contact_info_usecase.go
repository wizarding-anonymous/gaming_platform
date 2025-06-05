// File: backend/services/account-service/internal/app/usecase/contact_info_usecase.go
// account-service\internal\app\usecase\contact_info_usecase.go

package usecase

import (
	"context"
	"math/rand"
	"strconv"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/gaiming/account-service/internal/domain/entity"
	"github.com/gaiming/account-service/internal/domain/errors"
)

// ContactInfoRepository интерфейс для работы с репозиторием контактной информации
type ContactInfoRepository interface {
	Create(ctx context.Context, contactInfo *entity.ContactInfo) error
	GetByID(ctx context.Context, id string) (*entity.ContactInfo, error)
	GetByAccountID(ctx context.Context, accountID string, infoType string) ([]*entity.ContactInfo, error)
	GetByTypeAndValue(ctx context.Context, infoType, value string) (*entity.ContactInfo, error)
	Update(ctx context.Context, contactInfo *entity.ContactInfo) error
	Delete(ctx context.Context, id string) error
	SetPrimary(ctx context.Context, id string, accountID string) error
}

// VerificationCodeRepository интерфейс для работы с репозиторием кодов верификации
type VerificationCodeRepository interface {
	Create(ctx context.Context, code *entity.VerificationCode) error
	GetByContactInfoID(ctx context.Context, contactInfoID string) (*entity.VerificationCode, error)
	Delete(ctx context.Context, id string) error
}

// ContactInfoEventProducer интерфейс для отправки событий контактной информации
type ContactInfoEventProducer interface {
	PublishContactInfoCreated(ctx context.Context, contactInfo *entity.ContactInfo) error
	PublishContactInfoUpdated(ctx context.Context, contactInfo *entity.ContactInfo) error
	PublishContactInfoDeleted(ctx context.Context, contactInfoID string) error
	PublishVerificationRequested(ctx context.Context, contactInfo *entity.ContactInfo, code string) error
}

// ContactInfoUseCase реализует бизнес-логику для работы с контактной информацией
type ContactInfoUseCase struct {
	contactInfoRepo    ContactInfoRepository
	verificationRepo   VerificationCodeRepository
	accountRepo        AccountRepository
	eventProducer      ContactInfoEventProducer
	logger             *zap.SugaredLogger
}

// NewContactInfoUseCase создает новый экземпляр ContactInfoUseCase
func NewContactInfoUseCase(
	contactInfoRepo ContactInfoRepository,
	accountRepo AccountRepository,
	eventProducer ContactInfoEventProducer,
	logger *zap.SugaredLogger,
) *ContactInfoUseCase {
	return &ContactInfoUseCase{
		contactInfoRepo:    contactInfoRepo,
		accountRepo:        accountRepo,
		eventProducer:      eventProducer,
		logger:             logger,
	}
}

// GetContactInfo получает контактную информацию по ID аккаунта
func (uc *ContactInfoUseCase) GetContactInfo(ctx context.Context, accountID string, infoType string) ([]*entity.ContactInfo, error) {
	// Проверяем существование аккаунта
	_, err := uc.accountRepo.GetByID(ctx, accountID)
	if err != nil {
		if err == errors.ErrAccountNotFound {
			return nil, errors.ErrAccountNotFound
		}
		uc.logger.Errorw("Failed to get account", "error", err)
		return nil, errors.ErrInternalServerError
	}

	// Получаем контактную информацию
	contactInfo, err := uc.contactInfoRepo.GetByAccountID(ctx, accountID, infoType)
	if err != nil {
		uc.logger.Errorw("Failed to get contact info by account ID", "error", err)
		return nil, errors.ErrInternalServerError
	}

	return contactInfo, nil
}

// AddContactInfo добавляет новую контактную информацию
func (uc *ContactInfoUseCase) AddContactInfo(
	ctx context.Context,
	accountID string,
	infoType string,
	value string,
	isPrimary bool,
	visibility string,
) (*entity.ContactInfo, error) {
	// Проверяем существование аккаунта
	_, err := uc.accountRepo.GetByID(ctx, accountID)
	if err != nil {
		if err == errors.ErrAccountNotFound {
			return nil, errors.ErrAccountNotFound
		}
		uc.logger.Errorw("Failed to get account", "error", err)
		return nil, errors.ErrInternalServerError
	}

	// Проверяем валидность типа контактной информации
	contactInfoType := entity.ContactInfoType(infoType)
	if contactInfoType != entity.ContactInfoTypeEmail &&
		contactInfoType != entity.ContactInfoTypePhone &&
		contactInfoType != entity.ContactInfoTypeTelegram &&
		contactInfoType != entity.ContactInfoTypeDiscord {
		return nil, errors.ErrInvalidContactInfoType
	}

	// Проверяем валидность уровня видимости
	contactInfoVisibility := entity.ContactInfoVisibility(visibility)
	if contactInfoVisibility != entity.ContactInfoVisibilityPublic &&
		contactInfoVisibility != entity.ContactInfoVisibilityFriends &&
		contactInfoVisibility != entity.ContactInfoVisibilityPrivate {
		return nil, errors.ErrInvalidContactInfoValue
	}

	// Проверяем, существует ли уже такая контактная информация
	existingContactInfo, err := uc.contactInfoRepo.GetByTypeAndValue(ctx, infoType, value)
	if err == nil && existingContactInfo != nil {
		return nil, errors.ErrContactInfoAlreadyExists
	}

	// Создаем новую контактную информацию
	contactInfo := entity.NewContactInfo(accountID, contactInfoType, value, isPrimary, contactInfoVisibility)
	contactInfo.ID = uuid.New().String()

	// Сохраняем контактную информацию в БД
	if err := uc.contactInfoRepo.Create(ctx, contactInfo); err != nil {
		uc.logger.Errorw("Failed to create contact info", "error", err)
		return nil, errors.ErrInternalServerError
	}

	// Если это основная контактная информация, обновляем статус других контактов этого типа
	if isPrimary {
		if err := uc.contactInfoRepo.SetPrimary(ctx, contactInfo.ID, accountID); err != nil {
			uc.logger.Errorw("Failed to set contact info as primary", "error", err)
			// Не возвращаем ошибку, так как контактная информация уже создана
		}
	}

	// Публикуем событие о создании контактной информации
	if err := uc.eventProducer.PublishContactInfoCreated(ctx, contactInfo); err != nil {
		uc.logger.Errorw("Failed to publish contact info created event", "error", err)
		// Не возвращаем ошибку, так как это некритично
	}

	return contactInfo, nil
}

// UpdateContactInfo обновляет контактную информацию
func (uc *ContactInfoUseCase) UpdateContactInfo(
	ctx context.Context,
	id string,
	accountID string,
	value string,
	isPrimary bool,
	visibility string,
) (*entity.ContactInfo, error) {
	// Получаем контактную информацию
	contactInfo, err := uc.contactInfoRepo.GetByID(ctx, id)
	if err != nil {
		if err == errors.ErrContactInfoNotFound {
			return nil, errors.ErrContactInfoNotFound
		}
		uc.logger.Errorw("Failed to get contact info by ID", "error", err)
		return nil, errors.ErrInternalServerError
	}

	// Проверяем, принадлежит ли контактная информация указанному аккаунту
	if contactInfo.AccountID != accountID {
		return nil, errors.ErrForbidden
	}

	// Обновляем значение, если оно указано
	if value != "" && value != contactInfo.Value {
		contactInfo.UpdateValue(value)
	}

	// Обновляем уровень видимости, если он указан
	if visibility != "" {
		contactInfoVisibility := entity.ContactInfoVisibility(visibility)
		if contactInfoVisibility != entity.ContactInfoVisibilityPublic &&
			contactInfoVisibility != entity.ContactInfoVisibilityFriends &&
			contactInfoVisibility != entity.ContactInfoVisibilityPrivate {
			return nil, errors.ErrInvalidContactInfoValue
		}
		contactInfo.SetVisibility(contactInfoVisibility)
	}

	// Обновляем статус основной контактной информации, если он указан
	if isPrimary != contactInfo.IsPrimary {
		contactInfo.SetPrimary(isPrimary)
		if isPrimary {
			if err := uc.contactInfoRepo.SetPrimary(ctx, contactInfo.ID, accountID); err != nil {
				uc.logger.Errorw("Failed to set contact info as primary", "error", err)
				// Не возвращаем ошибку, так как контактная информация уже обновлена
			}
		}
	}

	// Сохраняем изменения в БД
	if err := uc.contactInfoRepo.Update(ctx, contactInfo); err != nil {
		uc.logger.Errorw("Failed to update contact info", "error", err)
		return nil, errors.ErrInternalServerError
	}

	// Публикуем событие об обновлении контактной информации
	if err := uc.eventProducer.PublishContactInfoUpdated(ctx, contactInfo); err != nil {
		uc.logger.Errorw("Failed to publish contact info updated event", "error", err)
		// Не возвращаем ошибку, так как это некритично
	}

	return contactInfo, nil
}

// DeleteContactInfo удаляет контактную информацию
func (uc *ContactInfoUseCase) DeleteContactInfo(ctx context.Context, id string, accountID string) error {
	// Получаем контактную информацию
	contactInfo, err := uc.contactInfoRepo.GetByID(ctx, id)
	if err != nil {
		if err == errors.ErrContactInfoNotFound {
			return errors.ErrContactInfoNotFound
		}
		uc.logger.Errorw("Failed to get contact info by ID", "error", err)
		return errors.ErrInternalServerError
	}

	// Проверяем, принадлежит ли контактная информация указанному аккаунту
	if contactInfo.AccountID != accountID {
		return errors.ErrForbidden
	}

	// Удаляем контактную информацию из БД
	if err := uc.contactInfoRepo.Delete(ctx, id); err != nil {
		uc.logger.Errorw("Failed to delete contact info", "error", err)
		return errors.ErrInternalServerError
	}

	// Публикуем событие об удалении контактной информации
	if err := uc.eventProducer.PublishContactInfoDeleted(ctx, id); err != nil {
		uc.logger.Errorw("Failed to publish contact info deleted event", "error", err)
		// Не возвращаем ошибку, так как это некритично
	}

	return nil
}

// RequestVerification запрашивает код верификации для контактной информации
func (uc *ContactInfoUseCase) RequestVerification(ctx context.Context, accountID string, contactInfoID string) (bool, string, int, error) {
	// Получаем контактную информацию
	contactInfo, err := uc.contactInfoRepo.GetByID(ctx, contactInfoID)
	if err != nil {
		if err == errors.ErrContactInfoNotFound {
			return false, "Contact information not found", 0, errors.ErrContactInfoNotFound
		}
		uc.logger.Errorw("Failed to get contact info by ID", "error", err)
		return false, "Internal server error", 0, errors.ErrInternalServerError
	}

	// Проверяем, принадлежит ли контактная информация указанному аккаунту
	if contactInfo.AccountID != accountID {
		return false, "Forbidden", 0, errors.ErrForbidden
	}

	// Генерируем код верификации
	code := generateVerificationCode()
	expiresInMinutes := 15

	// Создаем запись о коде верификации
	verificationCode := entity.NewVerificationCode(contactInfoID, code, expiresInMinutes)
	verificationCode.ID = uuid.New().String()

	// Сохраняем код верификации в БД
	if err := uc.verificationRepo.Create(ctx, verificationCode); err != nil {
		uc.logger.Errorw("Failed to create verification code", "error", err)
		return false, "Failed to create verification code", 0, errors.ErrInternalServerError
	}

	// Публикуем событие о запросе верификации
	if err := uc.eventProducer.PublishVerificationRequested(ctx, contactInfo, code); err != nil {
		uc.logger.Errorw("Failed to publish verification requested event", "error", err)
		// Не возвращаем ошибку, так как это некритично
	}

	return true, "Verification code sent", expiresInMinutes * 60, nil
}

// VerifyContactInfo проверяет код верификации для контактной информации
func (uc *ContactInfoUseCase) VerifyContactInfo(ctx context.Context, accountID string, contactInfoID string, code string) (bool, string, error) {
	// Получаем контактную информацию
	contactInfo, err := uc.contactInfoRepo.GetByID(ctx, contactInfoID)
	if err != nil {
		if err == errors.ErrContactInfoNotFound {
			return false, "Contact information not found", errors.ErrContactInfoNotFound
		}
		uc.logger.Errorw("Failed to get contact info by ID", "error", err)
		return false, "Internal server error", errors.ErrInternalServerError
	}

	// Проверяем, принадлежит ли контактная информация указанному аккаунту
	if contactInfo.AccountID != accountID {
		return false, "Forbidden", errors.ErrForbidden
	}

	// Получаем код верификации
	verificationCode, err := uc.verificationRepo.GetByContactInfoID(ctx, contactInfoID)
	if err != nil {
		uc.logger.Errorw("Failed to get verification code", "error", err)
		return false, "Verification code not found", errors.ErrInvalidVerificationCode
	}

	// Проверяем, не истек ли срок действия кода
	if verificationCode.IsExpired() {
		return false, "Verification code expired", errors.ErrVerificationCodeExpired
	}

	// Проверяем код
	if verificationCode.Code != code {
		return false, "Invalid verification code", errors.ErrInvalidVerificationCode
	}

	// Отмечаем контактную информацию как проверенную
	contactInfo.SetVerified(true)

	// Сохраняем изменения в БД
	if err := uc.contactInfoRepo.Update(ctx, contactInfo); err != nil {
		uc.logger.Errorw("Failed to update contact info", "error", err)
		return false, "Failed to update contact information", errors.ErrInternalServerError
	}

	// Удаляем использованный код верификации
	if err := uc.verificationRepo.Delete(ctx, verificationCode.ID); err != nil {
		uc.logger.Errorw("Failed to delete verification code", "error", err)
		// Не возвращаем ошибку, так как это некритично
	}

	// Публикуем событие об обновлении контактной информации
	if err := uc.eventProducer.PublishContactInfoUpdated(ctx, contactInfo); err != nil {
		uc.logger.Errorw("Failed to publish contact info updated event", "error", err)
		// Не возвращаем ошибку, так как это некритично
	}

	return true, "Contact information verified successfully", nil
}

// CheckContactInfoExists проверяет существование контактной информации
func (uc *ContactInfoUseCase) CheckContactInfoExists(ctx context.Context, infoType string, value string) (bool, string, error) {
	// Проверяем валидность типа контактной информации
	contactInfoType := entity.ContactInfoType(infoType)
	if contactInfoType != entity.ContactInfoTypeEmail &&
		contactInfoType != entity.ContactInfoTypePhone &&
		contactInfoType != entity.ContactInfoTypeTelegram &&
		contactInfoType != entity.ContactInfoTypeDiscord {
		return false, "", errors.ErrInvalidContactInfoType
	}

	// Проверяем, существует ли уже такая контактная информация
	contactInfo, err := uc.contactInfoRepo.GetByTypeAndValue(ctx, infoType, value)
	if err != nil {
		if err == errors.ErrContactInfoNotFound {
			return false, "", nil
		}
		uc.logger.Errorw("Failed to check if contact info exists", "error", err)
		return false, "", errors.ErrInternalServerError
	}

	return true, contactInfo.AccountID, nil
}

// generateVerificationCode генерирует случайный код верификации
func generateVerificationCode() string {
	rand.Seed(time.Now().UnixNano())
	code := rand.Intn(900000) + 100000 // 6-значный код
	return strconv.Itoa(code)
}
