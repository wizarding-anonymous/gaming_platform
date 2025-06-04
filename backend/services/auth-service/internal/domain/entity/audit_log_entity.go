package entity

import (
	"encoding/json"
	"time"
)

// AuditLogStatus defines the status of an audited action.
type AuditLogStatus string

const (
	AuditLogStatusSuccess AuditLogStatus = "success"
	AuditLogStatusFailure AuditLogStatus = "failure"
)

// AuditLog represents an entry in the audit log,
// mapping to the "audit_logs" table.
type AuditLog struct {
	ID          int64           `db:"id"`
	UserID      *string         `db:"user_id"`     // Nullable UUID
	Action      string          `db:"action"`
	TargetType  *string         `db:"target_type"` // Nullable
	TargetID    *string         `db:"target_id"`   // Nullable
	IPAddress   *string         `db:"ip_address"`  // Nullable
	UserAgent   *string         `db:"user_agent"`  // Nullable
	Status      AuditLogStatus  `db:"status"`
	Details     json.RawMessage `db:"details"` // Nullable JSONB
	CreatedAt   time.Time       `db:"created_at"`
}