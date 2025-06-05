// File: backend/services/auth-service/internal/infrastructure/database/audit_log_postgres_repository.go
package database

import (
	"context"
	"errors"
	"fmt"
	"strings" // For building dynamic queries

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gameplatform/auth-service/internal/domain/entity"
	"github.com/gameplatform/auth-service/internal/domain/repository"
)

type pgxAuditLogRepository struct {
	db *pgxpool.Pool
}

// NewPgxAuditLogRepository creates a new instance of pgxAuditLogRepository.
func NewPgxAuditLogRepository(db *pgxpool.Pool) repository.AuditLogRepository {
	return &pgxAuditLogRepository{db: db}
}

func (r *pgxAuditLogRepository) Create(ctx context.Context, logEntry *entity.AuditLog) error {
	// created_at has default, id is BIGSERIAL
	query := `
		INSERT INTO audit_logs (user_id, action, target_type, target_id, ip_address, user_agent, status, details, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`
	err := r.db.QueryRow(ctx, query,
		logEntry.UserID, logEntry.Action, logEntry.TargetType, logEntry.TargetID,
		logEntry.IPAddress, logEntry.UserAgent, logEntry.Status, logEntry.Details, logEntry.CreatedAt,
	).Scan(&logEntry.ID) // Scan the generated ID back into the struct

	if err != nil {
		// Not expecting unique constraint errors here unless id was manually set and clashed, which is unlikely for BIGSERIAL.
		return fmt.Errorf("failed to create audit log entry: %w", err)
	}
	return nil
}

func (r *pgxAuditLogRepository) FindByID(ctx context.Context, id int64) (*entity.AuditLog, error) {
	query := `
		SELECT id, user_id, action, target_type, target_id, ip_address, user_agent, status, details, created_at
		FROM audit_logs
		WHERE id = $1`
	logEntry := &entity.AuditLog{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&logEntry.ID, &logEntry.UserID, &logEntry.Action, &logEntry.TargetType, &logEntry.TargetID,
		&logEntry.IPAddress, &logEntry.UserAgent, &logEntry.Status, &logEntry.Details, &logEntry.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("audit log entry not found") // Placeholder for entity.ErrAuditLogNotFound
		}
		return nil, fmt.Errorf("failed to find audit log entry by ID: %w", err)
	}
	return logEntry, nil
}

func (r *pgxAuditLogRepository) List(ctx context.Context, params repository.ListAuditLogParams) ([]*entity.AuditLog, int, error) {
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

	if params.UserID != nil && *params.UserID != "" {
		addFilter("user_id =", *params.UserID)
	}
	if params.Action != nil && *params.Action != "" {
		addFilter("action ILIKE", "%"+*params.Action+"%") // Case-insensitive partial match
	}
	if params.TargetType != nil && *params.TargetType != "" {
		addFilter("target_type ILIKE", "%"+*params.TargetType+"%")
	}
	if params.TargetID != nil && *params.TargetID != "" {
		addFilter("target_id =", *params.TargetID)
	}
	if params.Status != nil && *params.Status != "" {
		addFilter("status =", *params.Status)
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

	// Get total count
	var total int
	err := r.db.QueryRow(ctx, countQuery.String(), args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	if total == 0 {
		return []*entity.AuditLog{}, 0, nil
	}
	
	// Add sorting
	if params.SortBy == "" {
		params.SortBy = "created_at"
	}
	if params.SortOrder == "" {
		params.SortOrder = "DESC"
	}
	baseQuery.WriteString(fmt.Sprintf(" ORDER BY %s %s", params.SortBy, params.SortOrder))

	// Add pagination
	if params.PerPage > 0 {
		baseQuery.WriteString(fmt.Sprintf(" LIMIT $%d", argCount))
		args = append(args, params.PerPage)
		argCount++
		if params.Page > 0 {
			offset := (params.Page - 1) * params.PerPage
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

	var logs []*entity.AuditLog
	for rows.Next() {
		logEntry := &entity.AuditLog{}
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