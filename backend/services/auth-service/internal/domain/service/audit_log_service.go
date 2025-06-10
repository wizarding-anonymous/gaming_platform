// File: backend/services/auth-service/internal/domain/service/audit_log_service.go
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid" // For generating AuditLog entry ID if not using BIGSERIAL from DB directly in entity
	"go.uber.org/zap"

	// "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/entity" // Using models now
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"    // For models.AuditLog, models.AuditLogStatus
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository" // For repository.ListAuditLogParams
	repoInterfaces "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/repository/interfaces" // For AuditLogRepository dep
)

// AuditLogRecorder defines the interface for recording audit trail events.
type AuditLogRecorder interface {
	RecordEvent(
		ctx context.Context,
		actorUserID *string, // User performing the action (can be nil)
		action string,       // Verb describing the action, e.g., "user_login_success"
		targetType *string,  // Type of entity being acted upon, e.g., "user", "role"
		targetID *string,    // ID of the entity being acted upon
		status models.AuditLogStatus, // "success" or "failure"
		details map[string]interface{}, // Additional context-specific details
		ipAddress *string,
		userAgent *string,
	) error

	// ListAuditLogs retrieves audit log entries based on specified parameters.
	// This might belong to a different service/interface if AuditLogRecorder is strictly for recording.
	// For now, keeping it as per existing file structure.
	ListAuditLogs(ctx context.Context, params repository.ListAuditLogParams) (logs []*models.AuditLog, totalCount int, err error)
}

type auditLogService struct { // Renamed from auditLogServiceImpl to align with typical Go naming
	auditRepo repoInterfaces.AuditLogRepository
	logger    *zap.Logger
}

// NewAuditLogService creates a new auditLogService that implements AuditLogRecorder.
func NewAuditLogService(auditRepo repoInterfaces.AuditLogRepository, logger *zap.Logger) AuditLogRecorder {
	return &auditLogService{
		auditRepo: auditRepo,
		logger:    logger.Named("audit_log_service"),
	}
}

// RecordEvent constructs an AuditLog entity and persists it using the repository.
func (s *auditLogService) RecordEvent(
	ctx context.Context,
	actorUserID *string,
	action string,
	targetType *string,
	targetID *string,
	status models.AuditLogStatus, // Now using models.AuditLogStatus directly
	details map[string]interface{},
	ipAddress *string,
	userAgent *string,
) error {

	var detailsJSON json.RawMessage
	var err error
	if details != nil && len(details) > 0 {
		detailsBytes, errMarshal := json.Marshal(details)
		if errMarshal != nil {
			s.logger.Error("Failed to marshal audit log details to JSON",
				zap.Error(errMarshal),
				zap.String("action", action),
				zap.Any("details_map", details))
			// Decide if this is a fatal error for the audit log, or log with details as string
			detailsJSON = json.RawMessage(fmt.Sprintf(`{"error": "failed to marshal details: %s"}`, errMarshal.Error()))
		} else {
			detailsJSON = detailsBytes
		}
	}

	var parsedActorUserID *uuid.UUID
	if actorUserID != nil && *actorUserID != "" {
		uid, errParse := uuid.Parse(*actorUserID)
		if errParse == nil {
			parsedActorUserID = &uid
		} else {
			s.logger.Warn("Could not parse actorUserID for audit log", zap.String("rawActorUserID", *actorUserID), zap.Error(errParse))
		}
	}

	logEntry := &models.AuditLog{
		UserID:      parsedActorUserID, // Changed from userID
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		Status:      status, // Already models.AuditLogStatus
		Details:     detailsJSON,
		// CreatedAt is set by DB default
	}

	err = s.auditRepo.Create(ctx, logEntry)
	if err != nil {
		s.logger.Error("Failed to create audit log entry in repository",
			zap.Error(err),
			zap.String("action", action),
			zap.Any("log_entry_for_debug", logEntry), // Be careful with PII in debug logs
		)
		// Depending on policy, this error might be returned or just logged (if audit is non-critical path)
		return fmt.Errorf("failed to record audit event: %w", err)
	}

	s.logger.Info("Audit event recorded",
		zap.String("action", action),
		zap.Stringp("actorUserID", actorUserID), // Changed from userID
		zap.Stringp("targetType", targetType),
		zap.Stringp("targetID", targetID),
		zap.String("status", string(status)), // Cast status to string for logging
	)
	return nil
}

// ListAuditLogs retrieves audit logs.
func (s *auditLogService) ListAuditLogs(ctx context.Context, params repository.ListAuditLogParams) ([]*models.AuditLog, int, error) {
	logs, total, err := s.auditRepo.List(ctx, params)
	if err != nil {
		s.logger.Error("Failed to list audit logs from repository", zap.Error(err))
		return nil, 0, fmt.Errorf("failed to list audit logs: %w", err)
	}
	return logs, total, nil
}

var _ AuditLogRecorder = (*auditLogService)(nil) // Ensure it implements the new interface name

// Note:
// - Assumes `repoInterfaces.AuditLogRepository` uses `models.AuditLog`.
// - `models.AuditLog` should have `UserID *uuid.UUID`.
// - `repository.ListAuditLogParams` should be compatible.
// - Parsing of `actorUserID` from `*string` to `*uuid.UUID` is included.
