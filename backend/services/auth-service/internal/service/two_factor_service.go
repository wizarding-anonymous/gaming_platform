// File: internal/service/two_factor_service.go

package service

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/repository/interfaces"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/kafka"
	"go.uber.org/zap"
)

// TwoFactorService предоставляет методы для работы с двухфакторной аутентификацией
type TwoFactorService struct {
	userRepo    interfaces.UserRepository
	kafkaClient *kafka.Client
	logger      *zap.Logger
	issuer      string
}

// NewTwoFactorService создает новый экземпляр TwoFactorService
func NewTwoFactorService(
	userRepo interfaces.UserRepository,
	kafkaClient *kafka.Client,
	logger *zap.Logger,
	issuer string,
) *TwoFactorService {
	return &TwoFactorService{
		userRepo:    userRepo,
		kafkaClient: kafkaClient,
		logger:      logger,
		issuer:      issuer,
	}
}

// GenerateSecret генерирует секретный ключ для TOTP
func (s *TwoFactorService) GenerateSecret(ctx context.Context, userID uuid.UUID) (*models.TwoFactorSecret, error) {
	// Получение пользователя
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for 2FA secret generation", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, err
	}

	// Генерация случайного секретного ключа
	secret := make([]byte, 20)
	_, err = rand.Read(secret)
	if err != nil {
		s.logger.Error("Failed to generate random secret", zap.Error(err))
		return nil, err
	}

	// Кодирование секретного ключа в base32
	secretBase32 := base32.StdEncoding.EncodeToString(secret)

	// Создание TOTP-ключа
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: user.Email,
		Secret:      secret,
	})
	if err != nil {
		s.logger.Error("Failed to generate TOTP key", zap.Error(err))
		return nil, err
	}

	// Формирование ответа
	result := &models.TwoFactorSecret{
		Secret:   secretBase32,
		QRCode:   key.URL(),
		RecoveryCodes: s.generateRecoveryCodes(),
	}

	return result, nil
}

// EnableTwoFactor включает двухфакторную аутентификацию для пользователя
func (s *TwoFactorService) EnableTwoFactor(ctx context.Context, userID uuid.UUID, secret string, code string) error {
	// Получение пользователя
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for 2FA enabling", zap.Error(err), zap.String("user_id", userID.String()))
		return err
	}

	// Проверка кода
	valid := totp.Validate(code, secret)
	if !valid {
		return models.ErrInvalidTOTPCode
	}

	// Включение 2FA
	user.TwoFactorEnabled = true
	user.TwoFactorSecret = secret
	user.UpdatedAt = time.Now()

	// Сохранение пользователя
	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.Error("Failed to update user for 2FA enabling", zap.Error(err), zap.String("user_id", userID.String()))
		return err
	}

	// Отправка события о включении 2FA
	event := models.TwoFactorEnabledEvent{
		UserID:    user.ID.String(),
		EnabledAt: user.UpdatedAt,
	}
	err = s.kafkaClient.PublishUserEvent(ctx, "user.2fa_enabled", event)
	if err != nil {
		s.logger.Error("Failed to publish 2FA enabled event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}

	return nil
}

// DisableTwoFactor отключает двухфакторную аутентификацию для пользователя
func (s *TwoFactorService) DisableTwoFactor(ctx context.Context, userID uuid.UUID, code string) error {
	// Получение пользователя
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for 2FA disabling", zap.Error(err), zap.String("user_id", userID.String()))
		return err
	}

	// Проверка, включена ли 2FA
	if !user.TwoFactorEnabled {
		return models.ErrTwoFactorNotEnabled
	}

	// Проверка кода
	valid := totp.Validate(code, user.TwoFactorSecret)
	if !valid {
		return models.ErrInvalidTOTPCode
	}

	// Отключение 2FA
	user.TwoFactorEnabled = false
	user.TwoFactorSecret = ""
	user.UpdatedAt = time.Now()

	// Сохранение пользователя
	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.Error("Failed to update user for 2FA disabling", zap.Error(err), zap.String("user_id", userID.String()))
		return err
	}

	// Отправка события об отключении 2FA
	event := models.TwoFactorDisabledEvent{
		UserID:     user.ID.String(),
		DisabledAt: user.UpdatedAt,
	}
	err = s.kafkaClient.PublishUserEvent(ctx, "user.2fa_disabled", event)
	if err != nil {
		s.logger.Error("Failed to publish 2FA disabled event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}

	return nil
}

// VerifyTOTP проверяет TOTP-код
func (s *TwoFactorService) VerifyTOTP(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	// Получение пользователя
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for TOTP verification", zap.Error(err), zap.String("user_id", userID.String()))
		return false, err
	}

	// Проверка, включена ли 2FA
	if !user.TwoFactorEnabled {
		return false, models.ErrTwoFactorNotEnabled
	}

	// Проверка кода
	valid := totp.Validate(code, user.TwoFactorSecret)
	return valid, nil
}

// generateRecoveryCodes генерирует коды восстановления
func (s *TwoFactorService) generateRecoveryCodes() []string {
	codes := make([]string, 10)
	for i := 0; i < 10; i++ {
		// Генерация случайных байтов
		b := make([]byte, 5)
		rand.Read(b)
		
		// Преобразование в строку
		codes[i] = fmt.Sprintf("%x", b)
	}
	return codes
}
