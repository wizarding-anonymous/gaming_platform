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
	Username            *string     `json:"username,omitempty"`
	Email               *string     `json:"email,omitempty"`
	Status              *UserStatus `json:"status,omitempty"`
	EmailVerifiedAt     *time.Time  `json:"email_verified_at,omitempty"` // Explicitly set verification
	FailedLoginAttempts *int        `json:"failed_login_attempts,omitempty"`
	LockoutUntil        *time.Time  `json:"lockout_until,omitempty"`     // To lock or unlock account
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
	}
}
