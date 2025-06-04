package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Session represents the session entity in the database,
// aligned with auth_data_model.md and schema after migration 000008.
type Session struct {
	ID             uuid.UUID       `json:"id" db:"id"`
	UserID         uuid.UUID       `json:"user_id" db:"user_id"`
	IPAddress      *string         `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent      *string         `json:"user_agent,omitempty" db:"user_agent"`
	DeviceInfo     json.RawMessage `json:"device_info,omitempty" db:"device_info"` // Stored as JSONB
	ExpiresAt      time.Time       `json:"expires_at" db:"expires_at"`
	CreatedAt      time.Time       `json:"created_at" db:"created_at"`           // Handled by DB default
	LastActivityAt time.Time       `json:"last_activity_at" db:"last_activity_at"` // Updated by app logic or trigger
	UpdatedAt      time.Time       `json:"updated_at" db:"updated_at"`           // Handled by DB trigger
}

// ListSessionsParams defines parameters for listing sessions.
type ListSessionsParams struct {
	Page        int  `json:"page"`
	PageSize    int  `json:"page_size"`
	ActiveOnly  bool `json:"active_only"` // If true, only return sessions where expires_at > NOW()
	UserID      uuid.UUID // Filter by UserID, if needed for admin purposes, otherwise GetUserSessions is specific
}

// CreateSessionRequest represents data for creating a new session.
// Typically used in service layer.
type CreateSessionRequest struct {
	UserID         uuid.UUID
	IPAddress      *string
	UserAgent      *string
	DeviceInfo     json.RawMessage
	SessionExpiresIn time.Duration // For calculating ExpiresAt
}


// SessionResponse structures the session data returned by API endpoints.
type SessionResponse struct {
	ID             uuid.UUID       `json:"id"`
	UserID         uuid.UUID       `json:"user_id"`
	IPAddress      *string         `json:"ip_address,omitempty"`
	UserAgent      *string         `json:"user_agent,omitempty"`
	DeviceInfo     json.RawMessage `json:"device_info,omitempty"`
	ExpiresAt      time.Time       `json:"expires_at"`
	CreatedAt      time.Time       `json:"created_at"`
	LastActivityAt time.Time       `json:"last_activity_at"`
	IsActive       bool            `json:"is_active"` // Calculated field
}

// ToResponse converts a Session model to an API SessionResponse.
func (s *Session) ToResponse() SessionResponse {
	return SessionResponse{
		ID:             s.ID,
		UserID:         s.UserID,
		IPAddress:      s.IPAddress,
		UserAgent:      s.UserAgent,
		DeviceInfo:     s.DeviceInfo,
		ExpiresAt:      s.ExpiresAt,
		CreatedAt:      s.CreatedAt,
		LastActivityAt: s.LastActivityAt,
		IsActive:       s.ExpiresAt.After(time.Now()), // Calculated
	}
}
