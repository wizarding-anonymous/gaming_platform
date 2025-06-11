// File: backend/services/auth-service/internal/service/two_factor_service.go

package service

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/repository" // Assuming MFASecretRepository is here
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/repository/interfaces"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/crypto"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/kafka"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/metrics" // Added metrics import
	"go.uber.org/zap"
)

// TwoFactorService предоставляет методы для работы с двухфакторной аутентификацией
type TwoFactorService struct {
	userRepo        interfaces.UserRepository
	mfaSecretRepo   repository.MFASecretRepository // Added MFASecretRepository
	kafkaClient     *kafka.Client
	logger          *zap.Logger
	issuer          string
	encryptionKey   []byte
	backupCodeCount int
}

// NewTwoFactorService создает новый экземпляр TwoFactorService
func NewTwoFactorService(
	userRepo interfaces.UserRepository,
	mfaSecretRepo repository.MFASecretRepository, // Added MFASecretRepository
	kafkaClient *kafka.Client,
	logger *zap.Logger,
	issuer string,
	cfg *config.MFAConfig,
) (*TwoFactorService, error) {
	key, err := hex.DecodeString(cfg.TOTPEncryptionKey)
	if err != nil {
		logger.Error("Failed to decode TOTP encryption key from hex", zap.Error(err))
		return nil, fmt.Errorf("failed to decode TOTP encryption key: %w", err)
	}
	if len(key) != 32 {
		logger.Error("TOTP encryption key must be 32 bytes (64 hex characters)", zap.Int("key_length_bytes", len(key)))
		return nil, fmt.Errorf("TOTP encryption key must be 32 bytes (64 hex characters), got %d bytes", len(key))
	}

	return &TwoFactorService{
		userRepo:        userRepo,
		mfaSecretRepo:   mfaSecretRepo,
		kafkaClient:     kafkaClient,
		logger:          logger,
		issuer:          issuer,
		encryptionKey:   key,
		backupCodeCount: cfg.TOTPBackupCodeCount,
	}, nil
}

// InitiateEnableTwoFactor генерирует секретный ключ для TOTP и сохраняет его в неактивном состоянии.
func (s *TwoFactorService) InitiateEnableTwoFactor(ctx context.Context, userID uuid.UUID) (*models.Enable2FAInitiateResponse, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for 2FA secret generation", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, err
	}

	// Генерация случайного секретного ключа TOTP
	rawSecretBytes := make([]byte, 20) // 20 bytes for a standard TOTP secret
	if _, err := rand.Read(rawSecretBytes); err != nil {
		s.logger.Error("Failed to generate random TOTP secret bytes", zap.Error(err))
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}
	rawSecretBase32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(rawSecretBytes)

	// Шифрование секрета перед сохранением
	encryptedSecretWithNonce, err := crypto.Encrypt(rawSecretBytes, s.encryptionKey)
	if err != nil {
		s.logger.Error("Failed to encrypt TOTP secret", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}
	encryptedSecretBase64 := base64.StdEncoding.EncodeToString(encryptedSecretWithNonce)

	// Удаляем предыдущий неактивированный TOTP секрет, если он есть
	if err := s.mfaSecretRepo.DeleteUnverifiedByUserIDAndType(ctx, userID, models.MFATypeTOTP); err != nil {
		s.logger.Warn("Failed to delete previous unverified TOTP secret, continuing", zap.Error(err), zap.String("user_id", userID.String()))
		// Non-fatal, proceed with creating new one
	}

	mfaSecret := &models.MFASecret{
		UserID:             userID,
		Type:               models.MFATypeTOTP,
		SecretKeyEncrypted: encryptedSecretBase64,
		Verified:           false,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}

	if err := s.mfaSecretRepo.Create(ctx, mfaSecret); err != nil {
		s.logger.Error("Failed to save MFA secret", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, fmt.Errorf("failed to save MFA secret: %w", err)
	}

	// Создание URL для QR-кода
	otpKey, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.issuer,
		AccountName: user.Email,     // Используем email пользователя в качестве имени аккаунта
		Secret:      rawSecretBytes, // Передаем сырые байты секрета
	})
	if err != nil {
		s.logger.Error("Failed to generate TOTP key URL for QR code", zap.Error(err))
		return nil, fmt.Errorf("failed to generate TOTP key URL: %w", err)
	}

	return &models.Enable2FAInitiateResponse{
		MFASecretID:    mfaSecret.ID,
		SecretKey:      rawSecretBase32, // Для ручного ввода
		QRCodeImageURL: otpKey.URL(),
		// Recovery codes are generated only after successful verification in VerifyAndActivateTwoFactor
	}, nil
}

// VerifyAndActivateTwoFactor проверяет TOTP-код и активирует 2FA для пользователя.
func (s *TwoFactorService) VerifyAndActivateTwoFactor(ctx context.Context, userID, mfaSecretID uuid.UUID, totpCode string) ([]string, error) {
	mfaSecret, err := s.mfaSecretRepo.FindByID(ctx, mfaSecretID)
	if err != nil {
		s.logger.Error("Failed to find MFA secret for activation", zap.Error(err), zap.String("mfa_secret_id", mfaSecretID.String()))
		return nil, models.ErrMFASecretNotFound
	}

	if mfaSecret.UserID != userID {
		s.logger.Warn("MFA secret does not belong to the user", zap.String("user_id", userID.String()), zap.String("mfa_secret_id", mfaSecretID.String()))
		return nil, models.ErrMFASecretNotFound // Or a permission error
	}
	if mfaSecret.Verified {
		s.logger.Warn("MFA secret already verified", zap.String("mfa_secret_id", mfaSecretID.String()))
		return nil, models.ErrMFAAlreadyVerified
	}
	if mfaSecret.Type != models.MFATypeTOTP {
		s.logger.Warn("MFA secret is not of TOTP type", zap.String("mfa_secret_id", mfaSecretID.String()))
		return nil, models.ErrMFAInvalidType
	}

	decodedCiphertext, err := base64.StdEncoding.DecodeString(mfaSecret.SecretKeyEncrypted)
	if err != nil {
		s.logger.Error("Failed to decode base64 encrypted secret for 2FA activation", zap.Error(err), zap.String("mfa_secret_id", mfaSecretID.String()))
		return nil, fmt.Errorf("failed to decode stored secret: %w", err)
	}
	decryptedSecretBytes, err := crypto.Decrypt(decodedCiphertext, s.encryptionKey)
	if err != nil {
		s.logger.Error("Failed to decrypt TOTP secret for 2FA activation", zap.Error(err), zap.String("mfa_secret_id", mfaSecretID.String()))
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}
	decryptedSecretBase32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(decryptedSecretBytes)

	valid := totp.Validate(totpCode, decryptedSecretBase32)
	if !valid {
		s.logger.Warn("Invalid TOTP code during 2FA activation", zap.String("user_id", userID.String()))
		metrics.TwoFactorVerificationAttemptsTotal.WithLabelValues("failure_activation_invalid_code").Inc()
		return nil, models.ErrInvalidTOTPCode
	}

	mfaSecret.Verified = true
	mfaSecret.UpdatedAt = time.Now()
	if err := s.mfaSecretRepo.Update(ctx, mfaSecret); err != nil {
		s.logger.Error("Failed to update MFA secret to verified", zap.Error(err), zap.String("mfa_secret_id", mfaSecretID.String()))
		return nil, fmt.Errorf("failed to activate MFA secret: %w", err)
	}

	// Обновляем статус TwoFactorEnabled у пользователя (транзитное поле)
	// Реальное хранение этого флага может быть в mfa_secrets.verified или денормализовано в users.
	user, err := s.userRepo.GetByID(ctx, userID)
	if err == nil {
		user.TwoFactorEnabled = true
		// Если бы users.mfa_enabled существовало в БД, здесь был бы userRepo.Update(ctx, user)
		// s.logger.Info("User's transient TwoFactorEnabled flag set to true", zap.String("user_id", userID.String()))
	} else {
		s.logger.Warn("Failed to get user to update transient TwoFactorEnabled flag", zap.Error(err), zap.String("user_id", userID.String()))
	}

	// В реальной реализации здесь должны генерироваться и сохраняться резервные коды,
	// связанные с mfaSecret.ID или userID. Для упрощения примера возвращаем
	// временно сгенерированные коды без сохранения.
	recoveryCodes := s.generateRecoveryCodes()

	// Отправка события о включении 2FA
	event := models.TwoFactorEnabledEvent{
		UserID:    userID.String(),
		EnabledAt: mfaSecret.UpdatedAt,
	}
	if err := s.kafkaClient.PublishUserEvent(ctx, "user.2fa_enabled", event); err != nil {
		s.logger.Error("Failed to publish 2FA enabled event", zap.Error(err), zap.String("user_id", userID.String()))
	}

	metrics.TwoFactorVerificationAttemptsTotal.WithLabelValues("success_activation").Inc()
	return recoveryCodes, nil
}

// DisableTwoFactor отключает двухфакторную аутентификацию для пользователя
func (s *TwoFactorService) DisableTwoFactor(ctx context.Context, userID uuid.UUID, code string) error {
	mfaSecret, err := s.mfaSecretRepo.FindByUserIDAndType(ctx, userID, models.MFATypeTOTP)
	if err != nil {
		s.logger.Error("Failed to find MFA secret for disabling", zap.Error(err), zap.String("user_id", userID.String()))
		return models.ErrTwoFactorNotEnabled // Or ErrMFASecretNotFound
	}
	if !mfaSecret.Verified {
		s.logger.Warn("Attempt to disable an unverified MFA secret", zap.String("user_id", userID.String()))
		return models.ErrMFANotVerified
	}

	decodedCiphertext, err := base64.StdEncoding.DecodeString(mfaSecret.SecretKeyEncrypted)
	if err != nil {
		s.logger.Error("Failed to decode base64 encrypted secret for disabling 2FA", zap.Error(err), zap.String("user_id", userID.String()))
		return fmt.Errorf("failed to decode stored secret: %w", err)
	}
	decryptedSecretBytes, err := crypto.Decrypt(decodedCiphertext, s.encryptionKey)
	if err != nil {
		s.logger.Error("Failed to decrypt TOTP secret for disabling 2FA", zap.Error(err), zap.String("user_id", userID.String()))
		return fmt.Errorf("failed to decrypt secret, cannot disable 2FA: %w", err)
	}
	decryptedSecretBase32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(decryptedSecretBytes)

	valid := totp.Validate(code, decryptedSecretBase32)
	if !valid {
		s.logger.Warn("Invalid TOTP code during 2FA disabling", zap.String("user_id", userID.String()))
		metrics.TwoFactorVerificationAttemptsTotal.WithLabelValues("failure_disable_invalid_code").Inc()
		return models.ErrInvalidTOTPCode
	}

	if err := s.mfaSecretRepo.DeleteByUserIDAndType(ctx, userID, models.MFATypeTOTP); err != nil {
		s.logger.Error("Failed to delete MFA secret", zap.Error(err), zap.String("user_id", userID.String()))
		return fmt.Errorf("failed to disable MFA: %w", err)
	}

	// Обновляем статус TwoFactorEnabled у пользователя (транзитное поле)
	user, err := s.userRepo.GetByID(ctx, userID)
	if err == nil {
		user.TwoFactorEnabled = false
		// Если бы users.mfa_enabled существовало в БД, здесь был бы userRepo.Update(ctx, user)
		// s.logger.Info("User's transient TwoFactorEnabled flag set to false", zap.String("user_id", userID.String()))
	} else {
		s.logger.Warn("Failed to get user to update transient TwoFactorEnabled flag", zap.Error(err), zap.String("user_id", userID.String()))
	}

	// Отправка события об отключении 2FA
	event := models.TwoFactorDisabledEvent{
		UserID:     userID.String(),
		DisabledAt: time.Now(), // Or mfaSecret.UpdatedAt if we update it before delete
	}
	if err := s.kafkaClient.PublishUserEvent(ctx, "user.2fa_disabled", event); err != nil {
		s.logger.Error("Failed to publish 2FA disabled event", zap.Error(err), zap.String("user_id", userID.String()))
	}

	metrics.TwoFactorVerificationAttemptsTotal.WithLabelValues("success_disable").Inc()
	return nil
}

// VerifyTOTP проверяет TOTP-код для логина
func (s *TwoFactorService) VerifyTOTP(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	mfaSecret, err := s.mfaSecretRepo.FindByUserIDAndType(ctx, userID, models.MFATypeTOTP)
	if err != nil {
		s.logger.Info("MFA secret not found for user during TOTP verification", zap.Error(err), zap.String("user_id", userID.String()))
		metrics.TwoFactorVerificationAttemptsTotal.WithLabelValues("failure_not_enabled").Inc()
		return false, models.ErrTwoFactorNotEnabled // Or ErrMFASecretNotFound
	}

	if !mfaSecret.Verified {
		s.logger.Warn("Attempt to verify TOTP with unverified MFA secret", zap.String("user_id", userID.String()))
		metrics.TwoFactorVerificationAttemptsTotal.WithLabelValues("failure_not_enabled").Inc() // Or a more specific "not_verified" status
		return false, models.ErrMFANotVerified
	}

	decodedCiphertext, err := base64.StdEncoding.DecodeString(mfaSecret.SecretKeyEncrypted)
	if err != nil {
		s.logger.Error("Failed to decode base64 encrypted secret for TOTP verification", zap.Error(err), zap.String("user_id", userID.String()))
		return false, fmt.Errorf("failed to decode stored secret: %w", err)
	}

	decryptedSecretBytes, err := crypto.Decrypt(decodedCiphertext, s.encryptionKey)
	if err != nil {
		s.logger.Error("Failed to decrypt TOTP secret for verification", zap.Error(err), zap.String("user_id", userID.String()))
		return false, fmt.Errorf("failed to decrypt secret for validation: %w", err)
	}
	decryptedSecretBase32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(decryptedSecretBytes)

	valid := totp.Validate(code, decryptedSecretBase32)
	if !valid {
		s.logger.Warn("Invalid TOTP code during verification", zap.String("user_id", userID.String()))
		metrics.TwoFactorVerificationAttemptsTotal.WithLabelValues("failure_login_invalid_code").Inc()
		// Не возвращаем ошибку, просто valid = false
	} else {
		metrics.TwoFactorVerificationAttemptsTotal.WithLabelValues("success_login").Inc()
	}
	return valid, nil
}

// generateRecoveryCodes генерирует коды восстановления (пока без сохранения)
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
