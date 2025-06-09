// File: backend/services/auth-service/internal/domain/models/audit_log.go
package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// AuditLogStatus defines the possible statuses for an audit log entry.
type AuditLogStatus string

const (
	AuditLogStatusSuccess AuditLogStatus = "success"
	AuditLogStatusFailure AuditLogStatus = "failure"
)

// AuditLog represents an audit log entry.
// Aligned with the 'audit_logs' table in auth_data_model.md.
type AuditLog struct {
	ID          int64           `json:"id" db:"id"` // BIGSERIAL
	UserID      *uuid.UUID      `json:"user_id,omitempty" db:"user_id"` // Actor performing the action (null if system action)
	Action      string          `json:"action" db:"action"`             // e.g., "login_success", "password_change"
	TargetType  *string         `json:"target_type,omitempty" db:"target_type"` // Optional: type of the entity acted upon
	TargetID    *string         `json:"target_id,omitempty" db:"target_id"`     // Optional: ID of the entity acted upon
	IPAddress   *string         `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent   *string         `json:"user_agent,omitempty" db:"user_agent"`
	Status      AuditLogStatus  `json:"status" db:"status"` // "success" or "failure"
	Details     json.RawMessage `json:"details,omitempty" db:"details"` // Additional context-specific details (JSONB)
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`     // Handled by DB default
}

// CreateAuditLogRequest contains data for creating a new audit log entry.
// This is typically used by the service layer.
type CreateAuditLogRequest struct {
	UserID     *uuid.UUID
	Action     string
	TargetType *string
	TargetID   *string
	IPAddress  *string
	UserAgent  *string
	Status     AuditLogStatus
	Details    json.RawMessage
}
