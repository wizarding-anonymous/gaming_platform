package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/config"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	"github.com/your-org/auth-service/internal/domain/models"
	"github.com/your-org/auth-service/internal/repository/redis"
	"go.uber.org/zap"
)

// TokenService представляет сервис для работы с токенами
type TokenService struct {
	redisClient *redis.RedisClient
	jwtConfig   config.JWTConfig
	logger      *zap.Logger
}

// NewTokenService создает новый экземпляр TokenService
func NewTokenService(redisClient *redis.RedisClient, jwtConfig config.JWTConfig, logger *zap.Logger) *TokenService {
	return &TokenService{
		redisClient: redisClient,
		jwtConfig:   jwtConfig,
		logger:      logger,
	}
}

// GenerateTokenPair генерирует пару токенов (access и refresh)
func (s *TokenService) GenerateTokenPair(ctx context.Context, user models.User) (models.TokenPair, error) {
	// Генерация access токена
	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return models.TokenPair{}, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Генерация refresh токена
	refreshToken, err := s.generateRefreshToken(user.ID)
	if err != nil {
		return models.TokenPair{}, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Сохранение refresh токена в кэше
	err = s.redisClient.StoreTokenInCache(ctx, refreshToken, user.ID, s.jwtConfig.RefreshToken.ExpiresIn)
	if err != nil {
		return models.TokenPair{}, fmt.Errorf("failed to store refresh token in cache: %w", err)
	}

	return models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(s.jwtConfig.AccessToken.ExpiresIn.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// RefreshTokens обновляет пару токенов по refresh токену
func (s *TokenService) RefreshTokens(ctx context.Context, refreshToken string) (models.TokenPair, error) {
	// Проверка refresh токена в кэше
	userID, err := s.redisClient.GetTokenFromCache(ctx, refreshToken)
	if err != nil {
		return models.TokenPair{}, domainErrors.ErrInvalidRefreshToken
	}

	// Удаление старого refresh токена из кэша
	err = s.redisClient.RemoveTokenFromCache(ctx, refreshToken)
	if err != nil {
		s.logger.Warn("Failed to remove old refresh token from cache", zap.Error(err))
	}

	// Получение пользователя
	// Здесь мы создаем минимальную модель пользователя, так как нам нужен только ID
	// В реальном сценарии мы бы получали пользователя из базы данных
	user := models.User{
		ID: userID,
	}

	// Генерация новой пары токенов
	return s.GenerateTokenPair(ctx, user)
}

// ValidateAccessToken проверяет валидность access токена
func (s *TokenService) ValidateAccessToken(ctx context.Context, tokenString string) (*jwt.Token, jwt.MapClaims, error) {
	// Проверка, находится ли токен в черном списке
	isBlacklisted, err := s.redisClient.IsBlacklisted(ctx, tokenString)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to check token blacklist: %w", err)
	}
	if isBlacklisted {
		return nil, nil, domainErrors.ErrRevokedToken
	}

	// Парсинг токена
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Проверка алгоритма подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtConfig.AccessToken.Secret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, nil, domainErrors.ErrExpiredToken
		}
		return nil, nil, domainErrors.ErrInvalidToken
	}

	// Проверка валидности токена
	if !token.Valid {
		return nil, nil, domainErrors.ErrInvalidToken
	}

	// Получение claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, domainErrors.ErrInvalidToken
	}

	return token, claims, nil
}

// RevokeToken отзывает токен
func (s *TokenService) RevokeToken(ctx context.Context, tokenString string) error {
	// Парсинг токена без проверки подписи
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.jwtConfig.AccessToken.Secret), nil
	})
	if err != nil {
		// Если токен не может быть распарсен, считаем его уже отозванным
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil
		}
		return domainErrors.ErrInvalidToken
	}

	// Получение claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return domainErrors.ErrInvalidToken
	}

	// Получение времени истечения токена
	exp, ok := claims["exp"].(float64)
	if !ok {
		return domainErrors.ErrInvalidToken
	}

	// Вычисление оставшегося времени жизни токена
	expiresAt := time.Unix(int64(exp), 0)
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// Токен уже истек
		return nil
	}

	// Добавление токена в черный список
	err = s.redisClient.AddToBlacklist(ctx, tokenString, ttl)
	if err != nil {
		return fmt.Errorf("failed to add token to blacklist: %w", err)
	}

	return nil
}

// RevokeRefreshToken отзывает refresh токен
func (s *TokenService) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	// Удаление refresh токена из кэша
	err := s.redisClient.RemoveTokenFromCache(ctx, refreshToken)
	if err != nil {
		return fmt.Errorf("failed to remove refresh token from cache: %w", err)
	}

	return nil
}

// generateAccessToken генерирует access токен
func (s *TokenService) generateAccessToken(user models.User) (string, error) {
	// Подготовка ролей для включения в токен
	roles := make([]string, 0, len(user.Roles))
	for _, role := range user.Roles {
		roles = append(roles, role.Name)
	}

	// Создание claims
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   user.ID.String(),
		"email": user.Email,
		"roles": roles,
		"iat":   now.Unix(),
		"exp":   now.Add(s.jwtConfig.AccessToken.ExpiresIn).Unix(),
	}

	// Создание токена
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Подписание токена
	tokenString, err := token.SignedString([]byte(s.jwtConfig.AccessToken.Secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// generateRefreshToken генерирует refresh токен
func (s *TokenService) generateRefreshToken(userID uuid.UUID) (string, error) {
	// Создание claims
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": userID.String(),
		"iat": now.Unix(),
		"exp": now.Add(s.jwtConfig.RefreshToken.ExpiresIn).Unix(),
	}

	// Создание токена
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Подписание токена
	tokenString, err := token.SignedString([]byte(s.jwtConfig.RefreshToken.Secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// GenerateEmailVerificationToken генерирует токен для подтверждения email
func (s *TokenService) GenerateEmailVerificationToken(userID uuid.UUID) (string, error) {
	// Создание claims
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":  userID.String(),
		"type": "email_verification",
		"iat":  now.Unix(),
		"exp":  now.Add(24 * time.Hour).Unix(), // Токен действителен 24 часа
	}

	// Создание токена
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Подписание токена
	tokenString, err := token.SignedString([]byte(s.jwtConfig.AccessToken.Secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateEmailVerificationToken проверяет валидность токена для подтверждения email
func (s *TokenService) ValidateEmailVerificationToken(tokenString string) (uuid.UUID, error) {
	// Парсинг токена
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Проверка алгоритма подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtConfig.AccessToken.Secret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return uuid.Nil, domainErrors.ErrExpiredToken
		}
		return uuid.Nil, domainErrors.ErrInvalidToken
	}

	// Проверка валидности токена
	if !token.Valid {
		return uuid.Nil, domainErrors.ErrInvalidToken
	}

	// Получение claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return uuid.Nil, domainErrors.ErrInvalidToken
	}

	// Проверка типа токена
	tokenType, ok := claims["type"].(string)
	if !ok || tokenType != "email_verification" {
		return uuid.Nil, domainErrors.ErrInvalidToken
	}

	// Получение ID пользователя
	userIDStr, ok := claims["sub"].(string)
	if !ok {
		return uuid.Nil, domainErrors.ErrInvalidToken
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, domainErrors.ErrInvalidToken
	}

	return userID, nil
}

// GeneratePasswordResetToken генерирует токен для сброса пароля
func (s *TokenService) GeneratePasswordResetToken(userID uuid.UUID) (string, error) {
	// Создание claims
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":  userID.String(),
		"type": "password_reset",
		"iat":  now.Unix(),
		"exp":  now.Add(1 * time.Hour).Unix(), // Токен действителен 1 час
	}

	// Создание токена
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Подписание токена
	tokenString, err := token.SignedString([]byte(s.jwtConfig.AccessToken.Secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidatePasswordResetToken проверяет валидность токена для сброса пароля
func (s *TokenService) ValidatePasswordResetToken(tokenString string) (uuid.UUID, error) {
	// Парсинг токена
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Проверка алгоритма подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtConfig.AccessToken.Secret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return uuid.Nil, domainErrors.ErrExpiredToken
		}
		return uuid.Nil, domainErrors.ErrInvalidToken
	}

	// Проверка валидности токена
	if !token.Valid {
		return uuid.Nil, domainErrors.ErrInvalidToken
	}

	// Получение claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return uuid.Nil, domainErrors.ErrInvalidToken
	}

	// Проверка типа токена
	tokenType, ok := claims["type"].(string)
	if !ok || tokenType != "password_reset" {
		return uuid.Nil, domainErrors.ErrInvalidToken
	}

	// Получение ID пользователя
	userIDStr, ok := claims["sub"].(string)
	if !ok {
		return uuid.Nil, domainErrors.ErrInvalidToken
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, domainErrors.ErrInvalidToken
	}

	return userID, nil
}
