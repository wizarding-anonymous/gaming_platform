package models

// LoginRequest DTO for user login.
type LoginRequest struct {
	Identifier string `json:"identifier" binding:"required"` // Can be email or username
	Password   string `json:"password" binding:"required"`
}

// LogoutRequest DTO for user logout (if it needs to be in this file for organization)
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}
