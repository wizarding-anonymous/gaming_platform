// File: internal/utils/jwt/claims.go

package jwt

import (
	"github.com/golang-jwt/jwt/v4"
)

// AccessTokenClaims представляет собой claims для access токена
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	UserID    string   `json:"user_id"`
	Username  string   `json:"username"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	TokenType string   `json:"token_type"`
}

// RefreshTokenClaims представляет собой claims для refresh токена
type RefreshTokenClaims struct {
	jwt.RegisteredClaims
	UserID    string `json:"user_id"`
	TokenType string `json:"token_type"`
}

// EmailVerificationClaims представляет собой claims для токена подтверждения email
type EmailVerificationClaims struct {
	jwt.RegisteredClaims
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	TokenType string `json:"token_type"`
}

// PasswordResetClaims представляет собой claims для токена сброса пароля
type PasswordResetClaims struct {
	jwt.RegisteredClaims
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	TokenType string `json:"token_type"`
}
