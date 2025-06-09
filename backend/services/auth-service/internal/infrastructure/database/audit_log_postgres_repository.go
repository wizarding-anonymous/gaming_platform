// File: backend/services/auth-service/internal/infrastructure/database/audit_log_postgres_repository.go
package database

import (
	"context"
	"errors"
	"fmt"
	"strings" // For building dynamic queries

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/google/uuid" // Required for uuid.UUID

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository"
)

type pgxAuditLogRepository struct {
	db *pgxpool.Pool
}

// NewPgxAuditLogRepository creates a new instance of pgxAuditLogRepository.
func NewPgxAuditLogRepository(db *pgxpool.Pool) repository.AuditLogRepository {
	return &pgxAuditLogRepository{db: db}
}

func (r *pgxAuditLogRepository) Create(ctx context.Context, logEntry *models.AuditLog) error {
	// created_at has default, id is BIGSERIAL
	query := `
		INSERT INTO audit_logs (user_id, action, target_type, target_id, ip_address, user_agent, status, details, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`
	// Note: logEntry.UserID is *uuid.UUID. It's correctly handled by pgx if nil.
	err := r.db.QueryRow(ctx, query,
		logEntry.UserID, logEntry.Action, logEntry.TargetType, logEntry.TargetID,
		logEntry.IPAddress, logEntry.UserAgent, logEntry.Status, logEntry.Details, logEntry.CreatedAt,
	).Scan(&logEntry.ID)

	if err != nil {
		return fmt.Errorf("failed to create audit log entry: %w", err)
	}
	return nil
}

func (r *pgxAuditLogRepository) FindByID(ctx context.Context, id int64) (*models.AuditLog, error) {
	query := `
		SELECT id, user_id, action, target_type, target_id, ip_address, user_agent, status, details, created_at
		FROM audit_logs
		WHERE id = $1`
	logEntry := &models.AuditLog{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&logEntry.ID, &logEntry.UserID, &logEntry.Action, &logEntry.TargetType, &logEntry.TargetID,
		&logEntry.IPAddress, &logEntry.UserAgent, &logEntry.Status, &logEntry.Details, &logEntry.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Consider defining and using domainErrors.ErrAuditLogNotFound
			return nil, errors.New("audit log entry not found")
		}
		return nil, fmt.Errorf("failed to find audit log entry by ID: %w", err)
	}
	return logEntry, nil
}

func (r *pgxAuditLogRepository) List(ctx context.Context, params repository.ListAuditLogParams) ([]*models.AuditLog, int, error) {
	var baseQuery strings.Builder
	baseQuery.WriteString(`SELECT id, user_id, action, target_type, target_id, ip_address, user_agent, status, details, created_at FROM audit_logs WHERE 1=1`)

	var countQuery strings.Builder
	countQuery.WriteString(`SELECT COUNT(*) FROM audit_logs WHERE 1=1`)

	args := []interface{}{}
	argCount := 1

	addFilter := func(condition string, value interface{}) {
		baseQuery.WriteString(fmt.Sprintf(" AND %s $%d", condition, argCount))
		countQuery.WriteString(fmt.Sprintf(" AND %s $%d", condition, argCount))
		args = append(args, value)
		argCount++
	}

	if params.UserID != nil { // Changed from: params.UserID != nil && *params.UserID != ""
		addFilter("user_id =", *params.UserID)
	}
	if params.Action != nil && *params.Action != "" {
		addFilter("action ILIKE", "%"+*params.Action+"%")
	}
	if params.TargetType != nil && *params.TargetType != "" {
		addFilter("target_type ILIKE", "%"+*params.TargetType+"%")
	}
	if params.TargetID != nil && *params.TargetID != "" {
		addFilter("target_id =", *params.TargetID)
	}
	if params.Status != nil { // Changed from: params.Status != nil && *params.Status != ""
		addFilter("status =", *params.Status) // *models.AuditLogStatus is string alias, direct use is fine
	}
	if params.IPAddress != nil && *params.IPAddress != "" {
		addFilter("ip_address =", *params.IPAddress)
	}
	if params.DateFrom != nil {
		addFilter("created_at >=", *params.DateFrom)
	}
	if params.DateTo != nil {
		addFilter("created_at <=", *params.DateTo)
	}

	var total int
	err := r.db.QueryRow(ctx, countQuery.String(), args...).Scan(&total)
	if err != nil {
		// If ErrNoRows, it means count is 0, not an application error.
		if errors.Is(err, pgx.ErrNoRows) {
            total = 0
        } else {
            return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
        }
	}

	if total == 0 {
		return []*models.AuditLog{}, 0, nil
	}
	
	if params.SortBy == "" {
		params.SortBy = "created_at" // Default sort column
	}
	// Basic validation for SortBy to prevent injection with column names
	// A more robust solution would be a map of allowed sort fields.
	allowedSortBy := map[string]string{"created_at": "created_at", "action": "action", "status": "status", "user_id": "user_id"}
	dbSortBy, ok := allowedSortBy[strings.ToLower(params.SortBy)]
	if !ok {
		dbSortBy = "created_at" // Default to created_at if invalid sort field provided
	}

	if strings.ToUpper(params.SortOrder) != "ASC" && strings.ToUpper(params.SortOrder) != "DESC" {
		params.SortOrder = "DESC" // Default sort order
	}
	baseQuery.WriteString(fmt.Sprintf(" ORDER BY %s %s", dbSortBy, params.SortOrder))

	if params.PageSize > 0 { // Changed from params.PerPage
		baseQuery.WriteString(fmt.Sprintf(" LIMIT $%d", argCount))
		args = append(args, params.PageSize) // Changed from params.PerPage
		argCount++
		if params.Page > 0 {
			offset := (params.Page - 1) * params.PageSize // Changed from params.PerPage
			baseQuery.WriteString(fmt.Sprintf(" OFFSET $%d", argCount))
			args = append(args, offset)
			argCount++
		}
	}
	
	rows, err := r.db.Query(ctx, baseQuery.String(), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*models.AuditLog // Changed from entity.AuditLog
	for rows.Next() {
		logEntry := &models.AuditLog{} // Changed from entity.AuditLog
		if err := rows.Scan(
			&logEntry.ID, &logEntry.UserID, &logEntry.Action, &logEntry.TargetType, &logEntry.TargetID,
			&logEntry.IPAddress, &logEntry.UserAgent, &logEntry.Status, &logEntry.Details, &logEntry.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan audit log entry during list: %w", err)
		}
		logs = append(logs, logEntry)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error after iterating audit log list: %w", err)
	}

	return logs, total, nil
}

var _ repository.AuditLogRepository = (*pgxAuditLogRepository)(nil)