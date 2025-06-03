// File: internal/service/telegram_service.go

package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
	"github.com/your-org/auth-service/internal/repository/interfaces"
	"github.com/your-org/auth-service/internal/utils/kafka"
	"go.uber.org/zap"
)

// TelegramService предоставляет методы для работы с аутентификацией через Telegram
type TelegramService struct {
	userRepo    interfaces.UserRepository
	tokenService *TokenService
	kafkaClient *kafka.Client
	logger      *zap.Logger
	botToken    string
}

// NewTelegramService создает новый экземпляр TelegramService
func NewTelegramService(
	userRepo interfaces.UserRepository,
	tokenService *TokenService,
	kafkaClient *kafka.Client,
	logger *zap.Logger,
	botToken string,
) *TelegramService {
	return &TelegramService{
		userRepo:    userRepo,
		tokenService: tokenService,
		kafkaClient: kafkaClient,
		logger:      logger,
		botToken:    botToken,
	}
}

// VerifyTelegramAuth проверяет данные аутентификации Telegram
func (s *TelegramService) VerifyTelegramAuth(ctx context.Context, data models.TelegramAuthRequest) (bool, error) {
	// Проверка времени авторизации
	authDate, err := strconv.ParseInt(data.AuthDate, 10, 64)
	if err != nil {
		s.logger.Error("Failed to parse auth date", zap.Error(err))
		return false, err
	}

	// Проверка, не истекло ли время авторизации (24 часа)
	if time.Now().Unix()-authDate > 86400 {
		return false, models.ErrTelegramAuthExpired
	}

	// Формирование строки для проверки
	checkString := fmt.Sprintf(
		"auth_date=%s\nfirst_name=%s\nid=%s\nusername=%s",
		data.AuthDate,
		data.FirstName,
		data.ID,
		data.Username,
	)

	// Создание HMAC-SHA256 хеша
	secretKey := sha256.Sum256([]byte("WebAppData:" + s.botToken))
	h := hmac.New(sha256.New, secretKey[:])
	h.Write([]byte(checkString))
	hash := hex.EncodeToString(h.Sum(nil))

	// Проверка хеша
	return hash == data.Hash, nil
}

// LinkTelegramAccount связывает аккаунт Telegram с пользователем
func (s *TelegramService) LinkTelegramAccount(ctx context.Context, userID uuid.UUID, telegramID string) error {
	// Получение пользователя
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for Telegram linking", zap.Error(err), zap.String("user_id", userID.String()))
		return err
	}

	// Проверка, не привязан ли уже Telegram ID к другому пользователю
	existingUser, err := s.userRepo.GetByTelegramID(ctx, telegramID)
	if err == nil && existingUser != nil && existingUser.ID != userID {
		return models.ErrTelegramIDAlreadyLinked
	}

	// Связывание аккаунта Telegram
	user.TelegramID = telegramID
	user.UpdatedAt = time.Now()

	// Сохранение пользователя
	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.Error("Failed to update user for Telegram linking", zap.Error(err), zap.String("user_id", userID.String()))
		return err
	}

	// Отправка события о связывании аккаунта Telegram
	event := models.TelegramLinkedEvent{
		UserID:     user.ID.String(),
		TelegramID: telegramID,
		LinkedAt:   user.UpdatedAt,
	}
	err = s.kafkaClient.PublishUserEvent(ctx, "user.telegram_linked", event)
	if err != nil {
		s.logger.Error("Failed to publish Telegram linked event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}

	return nil
}

// UnlinkTelegramAccount отвязывает аккаунт Telegram от пользователя
func (s *TelegramService) UnlinkTelegramAccount(ctx context.Context, userID uuid.UUID) error {
	// Получение пользователя
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for Telegram unlinking", zap.Error(err), zap.String("user_id", userID.String()))
		return err
	}

	// Проверка, привязан ли Telegram ID
	if user.TelegramID == "" {
		return models.ErrTelegramNotLinked
	}

	// Сохранение Telegram ID для события
	telegramID := user.TelegramID

	// Отвязывание аккаунта Telegram
	user.TelegramID = ""
	user.UpdatedAt = time.Now()

	// Сохранение пользователя
	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.Error("Failed to update user for Telegram unlinking", zap.Error(err), zap.String("user_id", userID.String()))
		return err
	}

	// Отправка события об отвязывании аккаунта Telegram
	event := models.TelegramUnlinkedEvent{
		UserID:       user.ID.String(),
		TelegramID:   telegramID,
		UnlinkedAt:   user.UpdatedAt,
	}
	err = s.kafkaClient.PublishUserEvent(ctx, "user.telegram_unlinked", event)
	if err != nil {
		s.logger.Error("Failed to publish Telegram unlinked event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}

	return nil
}

// LoginWithTelegram выполняет вход с использованием Telegram
func (s *TelegramService) LoginWithTelegram(ctx context.Context, data models.TelegramAuthRequest) (*models.TokenPair, *models.User, error) {
	// Проверка данных аутентификации Telegram
	valid, err := s.VerifyTelegramAuth(ctx, data)
	if err != nil {
		s.logger.Error("Failed to verify Telegram auth", zap.Error(err))
		return nil, nil, err
	}
	if !valid {
		return nil, nil, models.ErrInvalidTelegramAuth
	}

	// Поиск пользователя по Telegram ID
	user, err := s.userRepo.GetByTelegramID(ctx, data.ID)
	if err != nil {
		// Если пользователь не найден, можно создать нового или вернуть ошибку
		// В данном случае возвращаем ошибку, так как требуется предварительная привязка
		s.logger.Error("User not found by Telegram ID", zap.Error(err), zap.String("telegram_id", data.ID))
		return nil, nil, models.ErrUserNotFound
	}

	// Создание токенов
	tokenPair, err := s.tokenService.CreateTokenPair(ctx, user)
	if err != nil {
		s.logger.Error("Failed to create token pair", zap.Error(err), zap.String("user_id", user.ID.String()))
		return nil, nil, err
	}

	// Отправка события о входе через Telegram
	event := models.TelegramLoginEvent{
		UserID:    user.ID.String(),
		TelegramID: data.ID,
		LoginAt:   time.Now(),
	}
	err = s.kafkaClient.PublishUserEvent(ctx, "user.telegram_login", event)
	if err != nil {
		s.logger.Error("Failed to publish Telegram login event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}

	return tokenPair, user, nil
}
