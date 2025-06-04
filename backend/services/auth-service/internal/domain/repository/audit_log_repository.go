package repository

import (
	"context"
	"time"

	"github.com/gameplatform/auth-service/internal/domain/entity"
)

// ListAuditLogParams defines parameters for listing audit log entries.
type ListAuditLogParams struct {
	Page        int
	PerPage     int
	UserID      *string // Optional filter by user ID (UUID)
	Action      *string // Optional filter by action type
	TargetType  *string // Optional filter by target type
	TargetID    *string // Optional filter by target ID
	Status      *entity.AuditLogStatus // Optional filter by status
	IPAddress   *string // Optional filter by IP address
	DateFrom    *time.Time // Optional filter for entries created from this date
	DateTo      *time.Time // Optional filter for entries created up to this date
	SortBy      string     // e.g., "created_at"
	SortOrder   string     // "ASC" or "DESC"
}

// AuditLogRepository defines the interface for interacting with audit log data.
type AuditLogRepository interface {
	// Create persists a new audit log entry to the database.
	Create(ctx context.Context, logEntry *entity.AuditLog) error

	// FindByID retrieves an audit log entry by its unique ID (BIGSERIAL).
	// Returns entity.ErrAuditLogNotFound if not found.
	FindByID(ctx context.Context, id int64) (*entity.AuditLog, error)

	// List retrieves audit log entries based on specified parameters,
	// including pagination and filtering options.
	// Returns a slice of AuditLog entries, the total count of matching records, and an error if any.
	List(ctx context.Context, params ListAuditLogParams) ([]*entity.AuditLog, int, error)
}

// Note: entity.ErrAuditLogNotFound would be a custom error.
// Define in an appropriate error definitions file.
// Example:
// package entity
// import "errors"
// var ErrAuditLogNotFound = errors.New("audit log entry not found")
