// File: backend/services/auth-service/internal/domain/repository/audit_log_repository.go
package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors" // Ensure this import
)

// ListAuditLogParams defines parameters for listing audit log entries.
type ListAuditLogParams struct {
	Page        int
	PageSize    int // Renamed from PerPage for consistency
	UserID      *uuid.UUID // Optional filter by user ID (UUID)
	Action      *string    // Optional filter by action type
	TargetType  *string    // Optional filter by target type
	TargetID    *string    // Optional filter by target ID
	Status      *models.AuditLogStatus // Optional filter by status
	IPAddress   *string    // Optional filter by IP address
	DateFrom    *time.Time // Optional filter for entries created from this date
	DateTo      *time.Time // Optional filter for entries created up to this date
	SortBy      string     // e.g., "created_at"
	SortOrder   string     // "ASC" or "DESC"
}

// AuditLogRepository defines the interface for interacting with audit log data.
type AuditLogRepository interface {
	// Create persists a new audit log entry to the database.
	Create(ctx context.Context, logEntry *models.AuditLog) error

	// FindByID retrieves an audit log entry by its unique ID (BIGSERIAL).
	// Returns domainErrors.ErrNotFound if not found.
	FindByID(ctx context.Context, id int64) (*models.AuditLog, error)

	// List retrieves audit log entries based on specified parameters,
	// including pagination and filtering options.
	// Returns a slice of AuditLog entries, the total count of matching records, and an error if any.
	List(ctx context.Context, params ListAuditLogParams) ([]*models.AuditLog, int, error)
}

// Note: domainErrors.ErrNotFound or a specific ErrAuditLogNotFound should be used.
