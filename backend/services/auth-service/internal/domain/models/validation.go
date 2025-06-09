// File: backend/services/auth-service/internal/domain/models/validation.go
package models

import (
	// "github.com/google/uuid" // Not directly used in these DTOs, but UserID might be string representation
	// "time" // Not directly used in these DTOs, but Timestamps are int64
	"github.com/golang-jwt/jwt/v5" // For jwt.RegisteredClaims in IntrospectionResponse
)

// ValidateTokenRequest DTO for /validation/token
type ValidateTokenRequest struct {
	Token string `json:"token" binding:"required"`
}

// ValidateTokenResponse DTO
type ValidateTokenResponse struct {
	Valid       bool                   `json:"valid"`
	UserID      string                 `json:"user_id,omitempty"`
	Roles       []string               `json:"roles,omitempty"`
	Permissions []string               `json:"permissions,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	ExpiresAt   int64                  `json:"exp,omitempty"`
	IssuedAt    int64                  `json:"iat,omitempty"`
	Issuer      string                 `json:"iss,omitempty"`
	Audience    []string               `json:"aud,omitempty"` // Changed to []string to match jwt.RegisteredClaims
	Error       *ErrorResponseMessage `json:"error,omitempty"`
}

// ErrorResponseMessage for validation responses
type ErrorResponseMessage struct {
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

// CheckPermissionRequest DTO for /validation/permission
type CheckPermissionRequest struct {
	UserID       string  `json:"user_id" binding:"required,uuid"`
	Permission   string  `json:"permission" binding:"required"`
	ResourceID   *string `json:"resource_id,omitempty"`
}

// CheckPermissionResponse DTO
type CheckPermissionResponse struct {
	HasPermission bool `json:"has_permission"`
}

// IntrospectTokenRequest DTO for /validation/introspect
type IntrospectTokenRequest struct {
	Token string `json:"token" binding:"required"`
}

// IntrospectionResponse DTO (RFC 7662 style)
type IntrospectionResponse struct {
	Active      bool     `json:"active"`
	Scope       string   `json:"scope,omitempty"`
	ClientID    string   `json:"client_id,omitempty"`
	Username    string   `json:"username,omitempty"`
	TokenType   string   `json:"token_type,omitempty"`
	ExpiresAt   int64    `json:"exp,omitempty"`
	IssuedAt    int64    `json:"iat,omitempty"`
	NotBefore   int64    `json:"nbf,omitempty"`
	Subject     string   `json:"sub,omitempty"`
	Audience    []string `json:"aud,omitempty"`
	Issuer      string   `json:"iss,omitempty"`
	JWTID       string   `json:"jti,omitempty"`
	UserID      string   `json:"user_id,omitempty"`    // Custom claim, maps to sub or separate
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	SessionID   string   `json:"session_id,omitempty"`
	// Add other claims from your service.Claims struct as needed
	// Example from service.Claims (ensure consistency)
	// Claims service.Claims `json:"claims,omitempty"` // Or flatten them
}
