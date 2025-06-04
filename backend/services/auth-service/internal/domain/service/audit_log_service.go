package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid" // For generating AuditLog entry ID if not using BIGSERIAL from DB directly in entity
	"go.uber.org/zap"

	"github.com/gameplatform/auth-service/internal/domain/entity"
	"github.com/gameplatform/auth-service/internal/domain/repository"
)

// AuditLogService defines the interface for recording audit trail events.
type AuditLogService interface {
	RecordAuditEvent(
		ctx context.Context,
		userID *string, // User performing the action (nullable for system actions)
		action string, // A string identifier for the action (e.g., "USER_LOGIN_SUCCESS")
		targetType *string, // Type of the entity being acted upon (e.g., "user", "session")
		targetID *string,
		ipAddress *string,
		userAgent *string,
		status string,
		details map[string]interface{},
	) error

	// ListAuditLogs retrieves audit log entries based on specified parameters.
	ListAuditLogs(ctx context.Context, params repository.ListAuditLogParams) (logs []*models.AuditLog, totalCount int, err error)
}

type auditLogServiceImpl struct {
	auditRepo repository.AuditLogRepository // Should be repoInterfaces.AuditLogRepository
	logger    *zap.Logger
}

// AuditLogServiceConfig holds dependencies for AuditLogService.
// Consider renaming to auditLogServiceDependencies or passing directly to New if simple.
type AuditLogServiceConfig struct {
	AuditRepo repoInterfaces.AuditLogRepository // Use the aliased interface path
	Logger    *zap.Logger
}

// NewAuditLogService creates a new auditLogServiceImpl.
func NewAuditLogService(auditRepo repoInterfaces.AuditLogRepository, logger *zap.Logger) AuditLogService {
	return &auditLogServiceImpl{
		auditRepo: auditRepo,
		logger:    logger.Named("audit_log_service"),
	}
}

// RecordAuditEvent constructs an AuditLog entity and persists it using the repository.
// It now uses models.AuditLog and models.AuditLogStatus.
func (s *auditLogServiceImpl) RecordAuditEvent(
	ctx context.Context,
	userID *string,
	action string,
	targetType *string,
	targetID *string,
	ipAddress *string,
	userAgent *string,
	status string, // Should ideally be entity.AuditLogStatus type
	details map[string]interface{},
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

	// Convert string UserID to *uuid.UUID if necessary, or ensure AuditLog model handles *string.
	// For now, assume UserID in AuditLog is *uuid.UUID and helper function converts.
	var parsedUserID *uuid.UUID
	if userID != nil && *userID != "" {
		uid, errParse := uuid.Parse(*userID)
		if errParse == nil {
			parsedUserID = &uid
		} else {
			s.logger.Warn("Could not parse UserID for audit log", zap.String("rawUserID", *userID))
			// Decide if this is an error or log with nil UserID
		}
	}


	logEntry := &models.AuditLog{ // Changed to models.AuditLog
		UserID:      parsedUserID,
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		Status:      models.AuditLogStatus(status), // Cast to models.AuditLogStatus
		Details:     detailsJSON,
		// CreatedAt is set by DB default
	}

	err = s.auditRepo.Create(ctx, logEntry) // Ensure auditRepo.Create expects *models.AuditLog
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
		zap.Stringp("userID", userID),
		zap.Stringp("targetType", targetType),
		zap.Stringp("targetID", targetID),
		zap.String("status", status),
	)
	return nil
}

// ListAuditLogs retrieves audit logs.
func (s *auditLogServiceImpl) ListAuditLogs(ctx context.Context, params repository.ListAuditLogParams) ([]*models.AuditLog, int, error) {
	// Ensure auditRepo.List expects and returns compatible types (models.AuditLog)
	logs, total, err := s.auditRepo.List(ctx, params)
	if err != nil {
		s.logger.Error("Failed to list audit logs from repository", zap.Error(err))
		return nil, 0, fmt.Errorf("failed to list audit logs: %w", err)
	}
	return logs, total, nil
}


var _ AuditLogService = (*auditLogServiceImpl)(nil)

// Note: This refactoring assumes:
// 1. `repository.AuditLogRepository` interface and its implementation are updated to use `models.AuditLog`.
// 2. `models.AuditLog` and `models.AuditLogStatus` are correctly defined.
// 3. `repository.ListAuditLogParams` is defined and compatible.
// 4. UserID in AuditLog model is *uuid.UUID. Helper logic added for string to *uuid.UUID parsing.
//    If UserID in model is *string, then parsing is not needed here.
//    The model `models.AuditLog` (created in previous subtask) has `UserID *uuid.UUID`.
// The `uuid.NewString()` import was removed as ID is BIGSERIAL.
// The `status` parameter in RecordAuditEvent is cast to `models.AuditLogStatus`.
// The service method returns an error, allowing calling services to decide how to handle failures.
