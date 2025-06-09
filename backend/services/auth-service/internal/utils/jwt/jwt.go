// File: internal/utils/jwt/jwt.go

package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
)

var (
	// ErrInvalidToken возвращается, когда токен недействителен
	ErrInvalidToken = errors.New("invalid token")
	// ErrExpiredToken возвращается, когда токен истек
	ErrExpiredToken = errors.New("token has expired")
	// ErrTokenNotYetValid возвращается, когда токен еще не действителен
	ErrTokenNotYetValid = errors.New("token not yet valid")
	// ErrInvalidSigningMethod возвращается, когда метод подписи токена недействителен
	ErrInvalidSigningMethod = errors.New("invalid signing method")
	// ErrInvalidClaims возвращается, когда claims токена недействительны
	ErrInvalidClaims = errors.New("invalid token claims")
	// ErrKeyParsingFailed возвращается, когда не удалось разобрать ключ
	ErrKeyParsingFailed = errors.New("failed to parse RSA key")
)

// TokenType определяет тип JWT токена
type TokenType string

const (
	// AccessToken используется для доступа к защищенным ресурсам
	AccessToken TokenType = "access"
	// RefreshToken используется для обновления access токена
	RefreshToken TokenType = "refresh"
	// EmailVerificationToken используется для подтверждения email
	EmailVerificationToken TokenType = "email_verification"
	// PasswordResetToken используется для сброса пароля
	PasswordResetToken TokenType = "password_reset"
)

// TokenManager управляет JWT токенами
type TokenManager struct {
	config     *config.JWTConfig
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewTokenManager создает новый менеджер токенов
func NewTokenManager(cfg *config.JWTConfig) (*TokenManager, error) {
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(cfg.RSAPrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("%w: private key: %v", ErrKeyParsingFailed, err)
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cfg.RSAPublicKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("%w: public key: %v", ErrKeyParsingFailed, err)
	}

	return &TokenManager{
		config:     cfg,
		privateKey: privKey,
		publicKey:  pubKey,
	}, nil
}

// GenerateAccessToken генерирует новый access токен
func (tm *TokenManager) GenerateAccessToken(user *models.User, sessionID string) (string, error) {
	now := time.Now()
	claims := &AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(tm.config.AccessTokenTTL))), // Updated: AccessTokenTTL is already time.Duration
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    tm.config.Issuer,
			ID:        sessionID,
		},
		UserID:    user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Roles:     getRoleNames(user.Roles),
		TokenType: string(AccessToken),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(tm.privateKey)
}

// GenerateRefreshToken генерирует новый refresh токен
func (tm *TokenManager) GenerateRefreshToken(userID, sessionID string) (string, error) {
	now := time.Now()
	claims := &RefreshTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(tm.config.RefreshTokenTTL))), // Updated: RefreshTokenTTL is already time.Duration
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    tm.config.Issuer,
			ID:        sessionID,
		},
		UserID:    userID,
		TokenType: string(RefreshToken),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(tm.privateKey)
}

// GenerateEmailVerificationToken генерирует токен для подтверждения email
func (tm *TokenManager) GenerateEmailVerificationToken(userID, email string) (string, error) {
	now := time.Now()
	claims := &EmailVerificationClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tm.config.EmailVerificationToken.ExpiresIn)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    tm.config.Issuer,
		},
		UserID:    userID,
		Email:     email,
		TokenType: string(EmailVerificationToken),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(tm.privateKey)
}

// GeneratePasswordResetToken генерирует токен для сброса пароля
func (tm *TokenManager) GeneratePasswordResetToken(userID, email string) (string, error) {
	now := time.Now()
	claims := &PasswordResetClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tm.config.PasswordResetToken.ExpiresIn)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    tm.config.Issuer,
		},
		UserID:    userID,
		Email:     email,
		TokenType: string(PasswordResetToken),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(tm.privateKey)
}

// getKeyFunc is a helper for ParseToken and specific parse functions
func (tm *TokenManager) getKeyFunc(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, ErrInvalidSigningMethod
	}
	return tm.publicKey, nil
}

// ParseToken парсит и проверяет JWT токен, пытаясь определить его тип
func (tm *TokenManager) ParseToken(tokenString string) (jwt.Claims, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))

	var allClaims struct {
		AccessTokenClaims
		RefreshTokenClaims
		EmailVerificationClaims
		PasswordResetClaims
		TokenType string `json:"token_type"` // Common field to help determine type if others are ambiguous
	}

	// First parse without specific claims struct to get TokenType if possible
	// This is a simplified approach; a more robust way might involve trying to parse into each specific claim type.
	tempClaims := jwt.MapClaims{}
	token, err := parser.ParseWithClaims(tokenString, tempClaims, tm.getKeyFunc)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, ErrTokenNotYetValid
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	// Determine actual claims type based on "token_type" field or by trying to parse into specific types
	// For simplicity, this example will try parsing into AccessTokenClaims first, then others.
	// A more robust solution might inspect tempClaims["token_type"]

	accessTokenClaims := &AccessTokenClaims{}
	token, err = parser.ParseWithClaims(tokenString, accessTokenClaims, tm.getKeyFunc)
	if err == nil && token.Valid {
		if accessTokenClaims.TokenType == string(AccessToken) {
			return accessTokenClaims, nil
		}
	}

	refreshTokenClaims := &RefreshTokenClaims{}
	token, err = parser.ParseWithClaims(tokenString, refreshTokenClaims, tm.getKeyFunc)
	if err == nil && token.Valid {
		if refreshTokenClaims.TokenType == string(RefreshToken) {
			return refreshTokenClaims, nil
		}
	}

	emailVerificationClaims := &EmailVerificationClaims{}
	token, err = parser.ParseWithClaims(tokenString, emailVerificationClaims, tm.getKeyFunc)
	if err == nil && token.Valid {
		if emailVerificationClaims.TokenType == string(EmailVerificationToken) {
			return emailVerificationClaims, nil
		}
	}

	passwordResetClaims := &PasswordResetClaims{}
	token, err = parser.ParseWithClaims(tokenString, passwordResetClaims, tm.getKeyFunc)
	if err == nil && token.Valid {
		if passwordResetClaims.TokenType == string(PasswordResetToken) {
			return passwordResetClaims, nil
		}
	}

	// If we reach here, either the token type is unknown or some other error occurred during specific parsing attempts.
	// The initial generic parse already checked for major errors like expiration or invalid signature.
	return nil, ErrInvalidClaims // Or return the tempClaims if partial info is acceptable
}


// ParseAccessToken парсит и проверяет access токен
func (tm *TokenManager) ParseAccessToken(tokenString string) (*AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, tm.getKeyFunc)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, ErrTokenNotYetValid
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	if claims.TokenType != string(AccessToken) {
		return nil, fmt.Errorf("%w: invalid token type, expected %s, got %s", ErrInvalidToken, AccessToken, claims.TokenType)
	}

	return claims, nil
}

// ParseRefreshToken парсит и проверяет refresh токен
func (tm *TokenManager) ParseRefreshToken(tokenString string) (*RefreshTokenClaims, error) {
	claims := &RefreshTokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, tm.getKeyFunc)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, ErrTokenNotYetValid
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	if claims.TokenType != string(RefreshToken) {
		return nil, fmt.Errorf("%w: invalid token type, expected %s, got %s", ErrInvalidToken, RefreshToken, claims.TokenType)
	}

	return claims, nil
}

// ParseEmailVerificationToken парсит и проверяет токен подтверждения email
func (tm *TokenManager) ParseEmailVerificationToken(tokenString string) (*EmailVerificationClaims, error) {
	claims := &EmailVerificationClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, tm.getKeyFunc)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, ErrTokenNotYetValid
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	if claims.TokenType != string(EmailVerificationToken) {
		return nil, fmt.Errorf("%w: invalid token type, expected %s, got %s", ErrInvalidToken, EmailVerificationToken, claims.TokenType)
	}

	return claims, nil
}

// ParsePasswordResetToken парсит и проверяет токен сброса пароля
func (tm *TokenManager) ParsePasswordResetToken(tokenString string) (*PasswordResetClaims, error) {
	claims := &PasswordResetClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, tm.getKeyFunc)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, ErrTokenNotYetValid
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	if claims.TokenType != string(PasswordResetToken) {
		return nil, fmt.Errorf("%w: invalid token type, expected %s, got %s", ErrInvalidToken, PasswordResetToken, claims.TokenType)
	}

	return claims, nil
}

// getRoleNames извлекает имена ролей из списка ролей
func getRoleNames(roles []models.Role) []string {
	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.Name
	}
	return roleNames
}
