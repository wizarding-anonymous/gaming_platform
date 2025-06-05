// File: backend/services/auth-service/internal/domain/repository/postgres/audit_log_postgres_repository.go
package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	"github.com/your-org/auth-service/internal/domain/repository"
)

// AuditLogRepositoryPostgres implements repository.AuditLogRepository for PostgreSQL.
type AuditLogRepositoryPostgres struct {
	pool *pgxpool.Pool
	// logger *zap.Logger // Optional
}

// NewAuditLogRepositoryPostgres creates a new instance.
func NewAuditLogRepositoryPostgres(pool *pgxpool.Pool) *AuditLogRepositoryPostgres {
	return &AuditLogRepositoryPostgres{pool: pool}
}

// Create persists a new audit log entry.
func (r *AuditLogRepositoryPostgres) Create(ctx context.Context, logEntry *models.AuditLog) error {
	query := `
		INSERT INTO audit_logs (user_id, action, target_type, target_id, ip_address, user_agent, status, details)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	// id (BIGSERIAL) and created_at are handled by DB.
	_, err := r.pool.Exec(ctx, query,
		logEntry.UserID, logEntry.Action, logEntry.TargetType, logEntry.TargetID,
		logEntry.IPAddress, logEntry.UserAgent, logEntry.Status, logEntry.Details,
	)
	if err != nil {
		// Consider foreign key constraint on user_id if it's critical, though it's nullable.
		return fmt.Errorf("failed to create audit log: %w", err)
	}
	return nil
}

// FindByID retrieves an audit log entry by its ID.
func (r *AuditLogRepositoryPostgres) FindByID(ctx context.Context, id int64) (*models.AuditLog, error) {
	query := `
		SELECT id, user_id, action, target_type, target_id, ip_address, user_agent, status, details, created_at
		FROM audit_logs
		WHERE id = $1
	`
	log := &models.AuditLog{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&log.ID, &log.UserID, &log.Action, &log.TargetType, &log.TargetID,
		&log.IPAddress, &log.UserAgent, &log.Status, &log.Details, &log.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound // Or specific ErrAuditLogNotFound
		}
		return nil, fmt.Errorf("failed to find audit log by ID: %w", err)
	}
	return log, nil
}

// List retrieves audit log entries based on specified parameters.
func (r *AuditLogRepositoryPostgres) List(ctx context.Context, params repository.ListAuditLogParams) ([]*models.AuditLog, int, error) {
	var logs []*models.AuditLog
	var totalCount int

	baseQuery := `SELECT id, user_id, action, target_type, target_id, ip_address, user_agent, status, details, created_at FROM audit_logs`
	countQueryBase := `SELECT COUNT(*) FROM audit_logs`

	conditions := []string{}
	args := []interface{}{}
	argCount := 1

	addCondition := func(condition string, value interface{}) {
		conditions = append(conditions, fmt.Sprintf(condition, argCount))
		args = append(args, value)
		argCount++
	}

	if params.UserID != nil {
		addCondition("user_id = $%d", *params.UserID)
	}
	if params.Action != nil {
		addCondition("action = $%d", *params.Action)
	}
	if params.TargetType != nil {
		addCondition("target_type = $%d", *params.TargetType)
	}
	if params.TargetID != nil {
		addCondition("target_id = $%d", *params.TargetID)
	}
	if params.Status != nil {
		addCondition("status = $%d", *params.Status)
	}
	if params.IPAddress != nil {
		addCondition("ip_address = $%d", *params.IPAddress)
	}
	if params.DateFrom != nil {
		addCondition("created_at >= $%d", *params.DateFrom)
	}
	if params.DateTo != nil {
		addCondition("created_at <= $%d", *params.DateTo)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Get total count
	countQueryFull := countQueryBase + whereClause
	err := r.pool.QueryRow(ctx, countQueryFull, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	if totalCount == 0 {
		return logs, 0, nil
	}

	// Prepare query for fetching logs
	queryFull := baseQuery + whereClause

	orderBy := "created_at" // Default sort
	if params.SortBy != "" {
		// Basic validation to prevent SQL injection on SortBy
		// More robust validation might involve a map of allowed sort fields.
		if params.SortBy == "user_id" || params.SortBy == "action" || params.SortBy == "status" {
			orderBy = params.SortBy
		}
	}
	sortOrder := "DESC" // Default sort order
	if params.SortOrder != "" && (strings.ToUpper(params.SortOrder) == "ASC" || strings.ToUpper(params.SortOrder) == "DESC") {
		sortOrder = strings.ToUpper(params.SortOrder)
	}
	queryFull += fmt.Sprintf(" ORDER BY %s %s", orderBy, sortOrder)


	if params.PageSize > 0 {
		queryFull += fmt.Sprintf(" LIMIT $%d", argCount)
		args = append(args, params.PageSize)
		argCount++
		if params.Page > 0 {
			offset := (params.Page - 1) * params.PageSize
			queryFull += fmt.Sprintf(" OFFSET $%d", argCount)
			args = append(args, offset)
		}
	}

	rows, err := r.pool.Query(ctx, queryFull, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		log := &models.AuditLog{}
		errScan := rows.Scan(
			&log.ID, &log.UserID, &log.Action, &log.TargetType, &log.TargetID,
			&log.IPAddress, &log.UserAgent, &log.Status, &log.Details, &log.CreatedAt,
		)
		if errScan != nil {
			return nil, 0, fmt.Errorf("failed to scan audit log row: %w", errScan)
		}
		logs = append(logs, log)
	}
	if err = rows.Err(); err != nil {
        return nil, 0, fmt.Errorf("error iterating audit log rows: %w", err)
    }
	return logs, totalCount, nil
}

var _ repository.AuditLogRepository = (*AuditLogRepositoryPostgres)(nil)
