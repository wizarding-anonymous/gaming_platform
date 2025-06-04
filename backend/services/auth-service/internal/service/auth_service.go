// File: internal/service/auth_service.go

package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
	"github.com/your-org/auth-service/internal/repository/interfaces"
	"github.com/your-org/auth-service/internal/utils/kafka"
	"github.com/your-org/auth-service/internal/utils/security"
	"go.uber.org/zap"
)

// AuthService предоставляет методы для аутентификации и авторизации
type AuthService struct {
	userRepo      interfaces.UserRepository
	tokenService  *TokenService
	sessionService *SessionService
	kafkaClient   *kafka.Client
	logger        *zap.Logger
}

// NewAuthService создает новый экземпляр AuthService
func NewAuthService(
	userRepo interfaces.UserRepository,
	tokenService *TokenService,
	sessionService *SessionService,
	kafkaClient *kafka.Client,
	logger *zap.Logger,
) *AuthService {
	return &AuthService{
		userRepo:      userRepo,
		tokenService:  tokenService,
		sessionService: sessionService,
		kafkaClient:   kafkaClient,
		logger:        logger,
	}
}

// Register регистрирует нового пользователя
func (s *AuthService) Register(ctx context.Context, req models.CreateUserRequest) (*models.User, error) {
	// Проверка, существует ли пользователь с таким email
	existingUser, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		return nil, models.ErrEmailExists
	}

	// Проверка, существует ли пользователь с таким именем пользователя
	existingUser, err = s.userRepo.GetByUsername(ctx, req.Username)
	if err == nil && existingUser != nil {
		return nil, models.ErrUsernameExists
	}

	// Хеширование пароля
	hashedPassword, err := security.HashPassword(req.Password)
	if err != nil {
		s.logger.Error("Failed to hash password", zap.Error(err))
		return nil, err
	}

	// Создание пользователя
	user := &models.User{
		ID:             uuid.New(),
		Email:          req.Email,
		Username:       req.Username,
		HashedPassword: hashedPassword,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		EmailVerified:  false,
	}

	// Сохранение пользователя
	err = s.userRepo.Create(ctx, user)
	if err != nil {
		s.logger.Error("Failed to create user", zap.Error(err))
		return nil, err
	}

	// Отправка события о регистрации пользователя
	event := models.UserRegisteredEvent{
		UserID:    user.ID.String(),
		Email:     user.Email,
		Username:  user.Username,
		CreatedAt: user.CreatedAt,
	}
	err = s.kafkaClient.PublishUserEvent(ctx, "user.registered", event)
	if err != nil {
		s.logger.Error("Failed to publish user registered event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}

	return user, nil
}

// Login аутентифицирует пользователя
func (s *AuthService) Login(ctx context.Context, req models.LoginRequest) (*models.TokenPair, *models.User, error) {
	// Получение пользователя по email
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		s.logger.Error("User not found by email", zap.Error(err), zap.String("email", req.Email))
		return nil, nil, models.ErrInvalidCredentials
	}

	// Проверка пароля
	if !security.CheckPasswordHash(req.Password, user.HashedPassword) {
		return nil, nil, models.ErrInvalidCredentials
	}

	// Проверка, заблокирован ли пользователь
	if user.IsBlocked {
		return nil, nil, models.ErrUserBlocked
	}

	// Проверка, подтвержден ли email
	if !user.EmailVerified {
		return nil, nil, models.ErrEmailNotVerified
	}

	// Получение информации о клиенте
	userAgent := "unknown"
	ipAddress := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if ua, exists := md["user-agent"]; exists {
			userAgent = ua
		}
		if ip, exists := md["ip-address"]; exists {
			ipAddress = ip
		}
	}

	// Создание сессии
	session, err := s.sessionService.CreateSession(ctx, user.ID, userAgent, ipAddress)
	if err != nil {
		s.logger.Error("Failed to create session", zap.Error(err), zap.String("user_id", user.ID.String()))
		return nil, nil, err
	}

	// Создание токенов
	tokenPair, err := s.tokenService.CreateTokenPairWithSession(ctx, user, session.ID)
	if err != nil {
		s.logger.Error("Failed to create token pair", zap.Error(err), zap.String("user_id", user.ID.String()))
		return nil, nil, err
	}

	// Отправка события о входе пользователя
	event := models.UserLoginEvent{
		UserID:    user.ID.String(),
		Email:     user.Email,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		LoginAt:   time.Now(),
	}
	err = s.kafkaClient.PublishUserEvent(ctx, "user.login", event)
	if err != nil {
		s.logger.Error("Failed to publish user login event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}

	return tokenPair, user, nil
}

// RefreshToken обновляет токены
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*models.TokenPair, error) {
	// Валидация refresh токена
	claims, err := s.tokenService.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		s.logger.Error("Failed to validate refresh token", zap.Error(err))
		return nil, err
	}

	// Получение ID пользователя из claims
	userIDStr, ok := claims["sub"].(string)
	if !ok {
		s.logger.Error("Invalid user ID in refresh token")
		return nil, models.ErrInvalidToken
	}

	// Преобразование ID пользователя
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		s.logger.Error("Failed to parse user ID", zap.Error(err), zap.String("user_id", userIDStr))
		return nil, models.ErrInvalidToken
	}

	// Получение ID сессии из claims
	sessionIDStr, ok := claims["session_id"].(string)
	if !ok {
		s.logger.Error("Invalid session ID in refresh token")
		return nil, models.ErrInvalidToken
	}

	// Преобразование ID сессии
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		s.logger.Error("Failed to parse session ID", zap.Error(err), zap.String("session_id", sessionIDStr))
		return nil, models.ErrInvalidToken
	}

	// Получение пользователя
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("User not found", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, models.ErrUserNotFound
	}

	// Проверка, заблокирован ли пользователь
	if user.IsBlocked {
		return nil, models.ErrUserBlocked
	}

	// Проверка сессии
	session, err := s.sessionService.GetSession(ctx, sessionID)
	if err != nil {
		s.logger.Error("Session not found", zap.Error(err), zap.String("session_id", sessionID.String()))
		return nil, models.ErrSessionNotFound
	}

	// Проверка, активна ли сессия
	if !session.IsActive {
		return nil, models.ErrSessionInactive
	}

	// Создание новых токенов
	tokenPair, err := s.tokenService.CreateTokenPairWithSession(ctx, user, sessionID)
	if err != nil {
		s.logger.Error("Failed to create token pair", zap.Error(err), zap.String("user_id", user.ID.String()))
		return nil, err
	}

	// Отправка события об обновлении токена
	event := models.TokenRefreshedEvent{
		UserID:     user.ID.String(),
		SessionID:  sessionID.String(),
		RefreshedAt: time.Now(),
	}
	err = s.kafkaClient.PublishTokenEvent(ctx, "token.refreshed", event)
	if err != nil {
		s.logger.Error("Failed to publish token refreshed event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}

	return tokenPair, nil
}

// Logout выполняет выход пользователя
func (s *AuthService) Logout(ctx context.Context, accessToken, refreshToken string) error {
	// Валидация access токена
	_, claims, err := s.tokenService.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		s.logger.Error("Failed to validate access token", zap.Error(err))
		return err
	}

	// Получение ID сессии из claims
	sessionIDStr, ok := claims["session_id"].(string)
	if !ok {
		s.logger.Error("Invalid session ID in access token")
		return models.ErrInvalidToken
	}

	// Преобразование ID сессии
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		s.logger.Error("Failed to parse session ID", zap.Error(err), zap.String("session_id", sessionIDStr))
		return models.ErrInvalidToken
	}

	// Деактивация сессии
	err = s.sessionService.DeactivateSession(ctx, sessionID)
	if err != nil {
		s.logger.Error("Failed to deactivate session", zap.Error(err), zap.String("session_id", sessionID.String()))
		return err
	}

	// Добавление токенов в черный список
	err = s.tokenService.RevokeToken(ctx, accessToken) // Blacklist access token
	if err != nil {
		s.logger.Error("Failed to revoke access token", zap.Error(err))
	}

	// Revoke the specific refresh token from PostgreSQL
	if err := s.tokenService.RevokeRefreshToken(ctx, refreshToken); err != nil {
		s.logger.Error("Failed to revoke refresh token from DB", zap.Error(err), zap.String("session_id", sessionID.String()))
		// Non-fatal to logout flow, but needs monitoring
	}

	// Получение ID пользователя из claims
	userIDStr, ok := claims["sub"].(string)
	if !ok {
		s.logger.Error("Invalid user ID in access token")
		return nil
	}

	// Отправка события о выходе пользователя
	event := models.UserLogoutEvent{
		UserID:    userIDStr,
		SessionID: sessionID.String(),
		LogoutAt:  time.Now(),
	}
	err = s.kafkaClient.PublishUserEvent(ctx, "user.logout", event)
	if err != nil {
		s.logger.Error("Failed to publish user logout event", zap.Error(err), zap.String("user_id", userIDStr))
	}

	return nil
}

// LogoutAll выполняет выход пользователя из всех сессий
func (s *AuthService) LogoutAll(ctx context.Context, accessToken string) error {
	// Валидация access токена
	_, claims, err := s.tokenService.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		s.logger.Error("Failed to validate access token", zap.Error(err))
		return err
	}

	// Получение ID пользователя из claims
	userIDStr, ok := claims["sub"].(string)
	if !ok {
		s.logger.Error("Invalid user ID in access token")
		return models.ErrInvalidToken
	}

	// Преобразование ID пользователя
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		s.logger.Error("Failed to parse user ID", zap.Error(err), zap.String("user_id", userIDStr))
		return models.ErrInvalidToken
	}

	// Деактивация всех сессий пользователя (deletes session records)
	err = s.sessionService.DeactivateAllUserSessions(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to deactivate all user sessions", zap.Error(err), zap.String("user_id", userID.String()))
		// Not returning error here, as some sessions might have been deactivated.
		// Primary goal is to revoke tokens.
	}

	// Revoke all refresh tokens for the user from PostgreSQL
	if _, err := s.tokenService.RevokeAllRefreshTokensForUser(ctx, userID); err != nil {
		s.logger.Error("Failed to revoke all refresh tokens for user from DB", zap.Error(err), zap.String("user_id", userID.String()))
		// Non-fatal to logout flow overall
	}

	// Отправка события о выходе пользователя из всех сессий
	event := models.UserLogoutAllEvent{
		UserID:    userID.String(),
		LogoutAt:  time.Now(),
	}
	err = s.kafkaClient.PublishUserEvent(ctx, "user.logout_all", event)
	if err != nil {
		s.logger.Error("Failed to publish user logout all event", zap.Error(err), zap.String("user_id", userID.String()))
	}

	return nil
}

// VerifyEmail подтверждает email пользователя
func (s *AuthService) VerifyEmail(ctx context.Context, token string) error {
	// Валидация токена подтверждения email
	claims, err := s.tokenService.ValidateEmailVerificationToken(ctx, token)
	if err != nil {
		s.logger.Error("Failed to validate email verification token", zap.Error(err))
		return err
	}

	// Получение ID пользователя из claims
	userIDStr, ok := claims["sub"].(string)
	if !ok {
		s.logger.Error("Invalid user ID in email verification token")
		return models.ErrInvalidToken
	}

	// Преобразование ID пользователя
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		s.logger.Error("Failed to parse user ID", zap.Error(err), zap.String("user_id", userIDStr))
		return models.ErrInvalidToken
	}

	// Получение пользователя
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("User not found", zap.Error(err), zap.String("user_id", userID.String()))
		return models.ErrUserNotFound
	}

	// Проверка, подтвержден ли уже email
	if user.EmailVerified {
		return models.ErrEmailAlreadyVerified
	}

	// Подтверждение email
	user.EmailVerified = true
	user.UpdatedAt = time.Now()

	// Сохранение пользователя
	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.Error("Failed to update user", zap.Error(err), zap.String("user_id", user.ID.String()))
		return err
	}

	// Отправка события о подтверждении email
	event := models.EmailVerifiedEvent{
		UserID:     user.ID.String(),
		Email:      user.Email,
		VerifiedAt: user.UpdatedAt,
	}
	err = s.kafkaClient.PublishUserEvent(ctx, "user.email_verified", event)
	if err != nil {
		s.logger.Error("Failed to publish email verified event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}

	return nil
}

// ResendVerificationEmail повторно отправляет письмо с подтверждением email
func (s *AuthService) ResendVerificationEmail(ctx context.Context, email string) error {
	// Получение пользователя по email
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		s.logger.Error("User not found by email", zap.Error(err), zap.String("email", email))
		return models.ErrUserNotFound
	}

	// Проверка, подтвержден ли уже email
	if user.EmailVerified {
		return models.ErrEmailAlreadyVerified
	}

	// Создание токена подтверждения email
	token, err := s.tokenService.CreateEmailVerificationToken(ctx, user)
	if err != nil {
		s.logger.Error("Failed to create email verification token", zap.Error(err), zap.String("user_id", user.ID.String()))
		return err
	}

	// Отправка события о повторной отправке письма с подтверждением email
	event := models.VerificationEmailResentEvent{
		UserID:  user.ID.String(),
		Email:   user.Email,
		Token:   token,
		SentAt:  time.Now(),
	}
	err = s.kafkaClient.PublishUserEvent(ctx, "user.verification_email_resent", event)
	if err != nil {
		s.logger.Error("Failed to publish verification email resent event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}

	return nil
}

// ForgotPassword инициирует процесс восстановления пароля
func (s *AuthService) ForgotPassword(ctx context.Context, email string) error {
	// Получение пользователя по email
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		s.logger.Error("User not found by email", zap.Error(err), zap.String("email", email))
		return models.ErrUserNotFound
	}

	// Создание токена сброса пароля
	token, err := s.tokenService.CreatePasswordResetToken(ctx, user)
	if err != nil {
		s.logger.Error("Failed to create password reset token", zap.Error(err), zap.String("user_id", user.ID.String()))
		return err
	}

	// Отправка события о запросе сброса пароля
	event := models.PasswordResetRequestedEvent{
		UserID:     user.ID.String(),
		Email:      user.Email,
		Token:      token,
		RequestedAt: time.Now(),
	}
	err = s.kafkaClient.PublishUserEvent(ctx, "user.password_reset_requested", event)
	if err != nil {
		s.logger.Error("Failed to publish password reset requested event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}

	return nil
}

// ResetPassword сбрасывает пароль пользователя
func (s *AuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	// Валидация токена сброса пароля
	claims, err := s.tokenService.ValidatePasswordResetToken(ctx, token)
	if err != nil {
		s.logger.Error("Failed to validate password reset token", zap.Error(err))
		return err
	}

	// Получение ID пользователя из claims
	userIDStr, ok := claims["sub"].(string)
	if !ok {
		s.logger.Error("Invalid user ID in password reset token")
		return models.ErrInvalidToken
	}

	// Преобразование ID пользователя
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		s.logger.Error("Failed to parse user ID", zap.Error(err), zap.String("user_id", userIDStr))
		return models.ErrInvalidToken
	}

	// Получение пользователя
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("User not found", zap.Error(err), zap.String("user_id", userID.String()))
		return models.ErrUserNotFound
	}

	// Хеширование нового пароля
	hashedPassword, err := security.HashPassword(newPassword)
	if err != nil {
		s.logger.Error("Failed to hash password", zap.Error(err))
		return err
	}

	// Обновление пароля
	user.HashedPassword = hashedPassword
	user.UpdatedAt = time.Now()

	// Сохранение пользователя
	err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.Error("Failed to update user", zap.Error(err), zap.String("user_id", user.ID.String()))
		return err
	}

	// Деактивация всех сессий пользователя
	err = s.sessionService.DeactivateAllUserSessions(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to deactivate all user sessions", zap.Error(err), zap.String("user_id", userID.String()))
	}

	// Отправка события о сбросе пароля
	event := models.PasswordResetEvent{
		UserID:   user.ID.String(),
		Email:    user.Email,
		ResetAt:  user.UpdatedAt,
	}
	err = s.kafkaClient.PublishUserEvent(ctx, "user.password_reset", event)
	if err != nil {
		s.logger.Error("Failed to publish password reset event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}

	return nil
}
