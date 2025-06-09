// File: backend/services/auth-service/internal/domain/models/events.go
package models

import (
	"time"
	// "github.com/google/uuid" // Not needed for these event structs if IDs are strings
)

// UserRegisteredEvent is published when a new user completes registration.
type UserRegisteredEvent struct {
	UserID        string    `json:"user_id"`
	Email         string    `json:"email"`
	Username      string    `json:"username"`
	DisplayName   *string   `json:"display_name,omitempty"` // Optional
	InitialStatus string    `json:"initial_status"`
	CreatedAt     time.Time `json:"created_at"`
}

// EmailVerifiedEvent is published when a user successfully verifies their email.
type EmailVerifiedEvent struct {
	UserID     string    `json:"user_id"`
	Email      string    `json:"email"`
	VerifiedAt time.Time `json:"verified_at"`
}

// PasswordResetEvent is published when a user's password has been successfully reset.
type PasswordResetEvent struct {
	UserID  string    `json:"user_id"`
	Email   string    `json:"email"` // Included for recipient identification if needed
	ResetAt time.Time `json:"reset_at"`
}

// VerificationEmailResentEvent is published when a verification email has been resent.
type VerificationEmailResentEvent struct {
	UserID string    `json:"user_id"`
	Email  string    `json:"email"`
	Token  string    `json:"token"` // The new plain token
	SentAt time.Time `json:"sent_at"`
}

// PasswordResetRequestedEvent is published when a user requests a password reset.
type PasswordResetRequestedEvent struct {
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	Token       string    `json:"token"` // The plain password reset token
	RequestedAt time.Time `json:"requested_at"`
}

// UserLoginEvent is published upon successful user login.
type UserLoginEvent struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"` // Included for context
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	LoginAt   time.Time `json:"login_at"`
}

// UserLogoutEvent is published upon user logout from a single session.
type UserLogoutEvent struct {
	UserID    string    `json:"user_id"`
	SessionID string    `json:"session_id"`
	LogoutAt  time.Time `json:"logout_at"`
}

// UserLogoutAllEvent is published upon user logout from all sessions.
type UserLogoutAllEvent struct {
	UserID   string    `json:"user_id"`
	LogoutAt time.Time `json:"logout_at"`
}

// TokenRefreshedEvent is published when a token pair is refreshed.
type TokenRefreshedEvent struct {
	UserID    string    `json:"user_id"`
	SessionID string    `json:"session_id"`
	RefreshedAt time.Time `json:"refreshed_at"`
}

// PasswordChangedEvent is published when a user successfully changes their password while authenticated.
type PasswordChangedEvent struct {
	UserID    string    `json:"user_id"`
	ChangedAt time.Time `json:"changed_at"`
}

// --- RBAC Event Structs ---

// RoleCreatedEvent is published when a new role is created.
type RoleCreatedEvent struct {
	RoleID      string    `json:"role_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// RoleUpdatedEvent is published when a role's details are updated.
type RoleUpdatedEvent struct {
	RoleID      string    `json:"role_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RoleDeletedEvent is published when a role is deleted.
type RoleDeletedEvent struct {
	RoleID    string    `json:"role_id"`
	DeletedAt time.Time `json:"deleted_at"`
}

// RoleAssignedEvent is published when a role is assigned to a user.
type RoleAssignedEvent struct {
	UserID          string    `json:"user_id"`
	RoleID          string    `json:"role_id"`
	RoleName        string    `json:"role_name"` // For context
	AssignedAt      time.Time `json:"assigned_at"`
	ChangedByUserID string    `json:"changed_by_user_id,omitempty"` // Admin/system that made the change
}

// RoleRemovedEvent is published when a role is removed from a user.
// This specific event might be deprecated in favor of UserRolesChangedEvent.
type RoleRemovedEvent struct {
	UserID          string    `json:"user_id"`
	RoleID          string    `json:"role_id"` // The specific role that was removed
	RoleName        string    `json:"role_name"` // For context
	RemovedAt       time.Time `json:"removed_at"`
	ChangedByUserID string    `json:"changed_by_user_id,omitempty"`
}

// UserRolesChangedEvent is a more general event for when a user's role assignments change.
// This can cover both assignment and removal.
type UserRolesChangedEvent struct {
	UserID          string    `json:"user_id"`
	OldRoleIDs      []string  `json:"old_role_ids"` // List of role IDs before the change
	NewRoleIDs      []string  `json:"new_role_ids"` // List of role IDs after the change
	ChangedByUserID *string   `json:"changed_by_user_id,omitempty"` // Admin/system ID, use pointer for optional
	ChangeTimestamp time.Time `json:"change_timestamp"`
}


// Add other event structs as needed for Kafka integration,
// ensuring they align with `auth_event_streaming.md`.

// SessionCreatedEvent is published when a new session is created.
type SessionCreatedEvent struct {
	SessionID string    `json:"session_id"`
	UserID    string    `json:"user_id"`
	IPAddress string    `json:"ip_address,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// SessionDeactivatedEvent is published when a session is deactivated (deleted).
type SessionDeactivatedEvent struct {
	SessionID     string    `json:"session_id"`
	UserID        string    `json:"user_id"` // UserID associated with the session
	DeactivatedAt time.Time `json:"deactivated_at"`
}

// AllSessionsDeactivatedEvent is published when all sessions for a user are deactivated (deleted).
type AllSessionsDeactivatedEvent struct {
	UserID        string    `json:"user_id"`
	DeactivatedAt time.Time `json:"deactivated_at"`
}
