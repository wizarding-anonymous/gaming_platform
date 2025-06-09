// File: internal/domain/models/user.go
package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents the user entity in the database, aligned with auth_data_model.md after migration 000008.
type User struct {
	ID                  uuid.UUID  `json:"id" db:"id"`
	Username            string     `json:"username" db:"username"`
	Email               string     `json:"email" db:"email"`
	PasswordHash        string     `json:"-" db:"password_hash"`
	Status              UserStatus `json:"status" db:"status"` // 'active', 'inactive', 'blocked', 'pending_verification', 'deleted'
	EmailVerifiedAt     *time.Time `json:"email_verified_at,omitempty" db:"email_verified_at"`
	LastLoginAt         *time.Time `json:"last_login_at,omitempty" db:"last_login_at"`
	FailedLoginAttempts int        `json:"failed_login_attempts" db:"failed_login_attempts"`
	LockoutUntil        *time.Time `json:"lockout_until,omitempty" db:"lockout_until"`
	CreatedAt           time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt           *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
	Roles               []Role     `json:"roles,omitempty" db:"-"` // Loaded separately

	// TwoFactorEnabled can remain as a transient field, populated by service logic
	TwoFactorEnabled bool `json:"two_factor_enabled" db:"-"`
}

// UserStatus defines the possible statuses for a user.
type UserStatus string

const (
	UserStatusActive             UserStatus = "active"
	UserStatusInactive           UserStatus = "inactive"
	UserStatusBlocked            UserStatus = "blocked"
	UserStatusPendingVerification UserStatus = "pending_verification"
	UserStatusDeleted            UserStatus = "deleted"
)

// ListUsersParams defines parameters for listing users with pagination and filtering.
type ListUsersParams struct {
	Page             int        `json:"page"`
	PageSize         int        `json:"page_size"`
	Status           UserStatus `json:"status,omitempty"`
	UsernameContains string     `json:"username_contains,omitempty"`
	EmailContains    string     `json:"email_contains,omitempty"`
	// Add other filter fields as needed, e.g., CreatedAfter, CreatedBefore
}

// CreateUserRequest represents the data needed to create a new user.
// Typically used in service layer, not directly in repository.
type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"` // Plain password, to be hashed by service
}

// UpdateUserRequest represents data for updating a user.
// Typically used in service layer.
type UpdateUserRequest struct {
	Username            *string     `json:"username,omitempty" validate:"omitempty,min=3,max=50"`
	Email               *string     `json:"email,omitempty" validate:"omitempty,email"`
	// Status field update might be a separate admin endpoint or handled by specific actions like email verification.
}

// ChangePasswordRequest represents the DTO for a user changing their own password.
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=100"`
}

// VerifyEmailRequest DTO for email verification.
type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

// ResendVerificationRequest DTO for resending email verification.
type ResendVerificationRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ForgotPasswordRequest DTO for initiating password reset.
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordRequest DTO for resetting password with a token.
type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=100"`
}


// UserResponse structures the user data returned by API endpoints.
type UserResponse struct {
	ID                  uuid.UUID  `json:"id"`
	Username            string     `json:"username"`
	Email               string     `json:"email"`
	Status              UserStatus `json:"status"`
	EmailVerifiedAt     *time.Time `json:"email_verified_at,omitempty"`
	LastLoginAt         *time.Time `json:"last_login_at,omitempty"`
	FailedLoginAttempts int        `json:"failed_login_attempts"`
	LockoutUntil        *time.Time `json:"lockout_until,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	Roles               []string   `json:"roles,omitempty"`
	TwoFactorEnabled    bool       `json:"two_factor_enabled"`
}

// ToResponse converts a User model to an API UserResponse.
func (u *User) ToResponse() UserResponse {
	roleNames := make([]string, len(u.Roles))
	for i, r := range u.Roles {
		roleNames[i] = r.Name // Assuming Role struct has a Name field
	}
	return UserResponse{
		ID:                  u.ID,
		Username:            u.Username,
		Email:               u.Email,
		Status:              u.Status,
		EmailVerifiedAt:     u.EmailVerifiedAt,
		LastLoginAt:         u.LastLoginAt,
		FailedLoginAttempts: u.FailedLoginAttempts,
		LockoutUntil:        u.LockoutUntil,
		CreatedAt:           u.CreatedAt,
		UpdatedAt:           u.UpdatedAt,
		Roles:               roleNames,
		TwoFactorEnabled:    u.TwoFactorEnabled, // Include in response
	}
}

// Role struct needs to be defined for u.Roles to compile.
// This is a minimal definition. A more complete one might exist elsewhere
// or be part of the `auth_microservice_specification_final.md`.
type Role struct {
	ID          uuid.UUID `json:"id" db:"id"` // Or string, depending on actual schema
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description,omitempty" db:"description"`
	// Permissions []Permission `json:"permissions,omitempty" db:"-"` // Loaded separately
}
