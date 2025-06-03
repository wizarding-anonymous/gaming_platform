// File: internal/utils/jwt/jwt.go

package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/domain/models"
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
	config *config.JWTConfig
}

// NewTokenManager создает новый менеджер токенов
func NewTokenManager(config *config.JWTConfig) *TokenManager {
	return &TokenManager{
		config: config,
	}
}

// GenerateAccessToken генерирует новый access токен
func (tm *TokenManager) GenerateAccessToken(user *models.User, sessionID string) (string, error) {
	now := time.Now()
	claims := &AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(tm.config.AccessTokenTTL) * time.Minute)),
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

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(tm.config.Secret))
}

// GenerateRefreshToken генерирует новый refresh токен
func (tm *TokenManager) GenerateRefreshToken(userID, sessionID string) (string, error) {
	now := time.Now()
	claims := &RefreshTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(tm.config.RefreshTokenTTL) * time.Hour)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    tm.config.Issuer,
			ID:        sessionID,
		},
		UserID:    userID,
		TokenType: string(RefreshToken),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(tm.config.Secret))
}

// GenerateEmailVerificationToken генерирует токен для подтверждения email
func (tm *TokenManager) GenerateEmailVerificationToken(userID, email string) (string, error) {
	now := time.Now()
	claims := &EmailVerificationClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(tm.config.EmailVerificationTokenTTL) * time.Hour)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    tm.config.Issuer,
		},
		UserID:    userID,
		Email:     email,
		TokenType: string(EmailVerificationToken),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(tm.config.Secret))
}

// GeneratePasswordResetToken генерирует токен для сброса пароля
func (tm *TokenManager) GeneratePasswordResetToken(userID, email string) (string, error) {
	now := time.Now()
	claims := &PasswordResetClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(tm.config.PasswordResetTokenTTL) * time.Hour)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    tm.config.Issuer,
		},
		UserID:    userID,
		Email:     email,
		TokenType: string(PasswordResetToken),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(tm.config.Secret))
}

// ParseToken парсит и проверяет JWT токен
func (tm *TokenManager) ParseToken(tokenString string) (jwt.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidSigningMethod
		}
		return []byte(tm.config.Secret), nil
	})

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

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok {
		// Пробуем другие типы claims
		token, err = jwt.ParseWithClaims(tokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(tm.config.Secret), nil
		})
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
		}
		
		claims, ok := token.Claims.(*RefreshTokenClaims)
		if !ok {
			// Пробуем другие типы claims
			token, err = jwt.ParseWithClaims(tokenString, &EmailVerificationClaims{}, func(token *jwt.Token) (interface{}, error) {
				return []byte(tm.config.Secret), nil
			})
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
			}
			
			claims, ok := token.Claims.(*EmailVerificationClaims)
			if !ok {
				// Пробуем другие типы claims
				token, err = jwt.ParseWithClaims(tokenString, &PasswordResetClaims{}, func(token *jwt.Token) (interface{}, error) {
					return []byte(tm.config.Secret), nil
				})
				if err != nil {
					return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
				}
				
				claims, ok := token.Claims.(*PasswordResetClaims)
				if !ok {
					return nil, ErrInvalidClaims
				}
				return claims, nil
			}
			return claims, nil
		}
		return claims, nil
	}

	return claims, nil
}

// ParseAccessToken парсит и проверяет access токен
func (tm *TokenManager) ParseAccessToken(tokenString string) (*AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidSigningMethod
		}
		return []byte(tm.config.Secret), nil
	})

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

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok {
		return nil, ErrInvalidClaims
	}

	if claims.TokenType != string(AccessToken) {
		return nil, fmt.Errorf("%w: invalid token type", ErrInvalidToken)
	}

	return claims, nil
}

// ParseRefreshToken парсит и проверяет refresh токен
func (tm *TokenManager) ParseRefreshToken(tokenString string) (*RefreshTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidSigningMethod
		}
		return []byte(tm.config.Secret), nil
	})

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

	claims, ok := token.Claims.(*RefreshTokenClaims)
	if !ok {
		return nil, ErrInvalidClaims
	}

	if claims.TokenType != string(RefreshToken) {
		return nil, fmt.Errorf("%w: invalid token type", ErrInvalidToken)
	}

	return claims, nil
}

// ParseEmailVerificationToken парсит и проверяет токен подтверждения email
func (tm *TokenManager) ParseEmailVerificationToken(tokenString string) (*EmailVerificationClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &EmailVerificationClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidSigningMethod
		}
		return []byte(tm.config.Secret), nil
	})

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

	claims, ok := token.Claims.(*EmailVerificationClaims)
	if !ok {
		return nil, ErrInvalidClaims
	}

	if claims.TokenType != string(EmailVerificationToken) {
		return nil, fmt.Errorf("%w: invalid token type", ErrInvalidToken)
	}

	return claims, nil
}

// ParsePasswordResetToken парсит и проверяет токен сброса пароля
func (tm *TokenManager) ParsePasswordResetToken(tokenString string) (*PasswordResetClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &PasswordResetClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidSigningMethod
		}
		return []byte(tm.config.Secret), nil
	})

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

	claims, ok := token.Claims.(*PasswordResetClaims)
	if !ok {
		return nil, ErrInvalidClaims
	}

	if claims.TokenType != string(PasswordResetToken) {
		return nil, fmt.Errorf("%w: invalid token type", ErrInvalidToken)
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
