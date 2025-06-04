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
