// File: backend/services/auth-service/internal/domain/models/auth_dtos.go
package models

// LoginRequest DTO for user login.
type LoginRequest struct {
	Identifier string `json:"identifier" binding:"required"` // Can be email or username
	Password   string `json:"password" binding:"required"`
}

// RegisterRequest DTO for user registration.
type RegisterRequest struct {
	Username     string `json:"username" binding:"required,min=3,max=50"`
	Email        string `json:"email" binding:"required,email"`
	Password     string `json:"password" binding:"required,min=8,max=100"`
	CaptchaToken string `json:"captcha_token,omitempty"`
}

// LogoutRequest DTO for user logout (if it needs to be in this file for organization)
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}
