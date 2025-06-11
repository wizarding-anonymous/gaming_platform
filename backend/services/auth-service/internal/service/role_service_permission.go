// File: backend/services/auth-service/internal/service/role_service_permission.go

package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	kafkaEvents "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka"
	"go.uber.org/zap"
)

// AssignPermissionToRole assigns a permission to a role.
// actorID is the ID of the admin performing the action.
func (s *RoleService) AssignPermissionToRole(ctx context.Context, roleID string, permissionID string, actorID *uuid.UUID) error {
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists {
			ipAddress = val
		}
		if val, exists := md["user-agent"]; exists {
			userAgent = val
		}
	}
	var auditDetails = make(map[string]interface{})
	targetRoleIDStr := &roleID
	auditDetails["permission_id_assigned"] = permissionID

	_, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		s.logger.Error("AssignPermissionToRole: Role not found", zap.String("roleID", roleID), zap.Error(err))
		auditDetails["error"] = domainErrors.ErrRoleNotFound.Error()
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorID, "role_permission_assign", models.AuditLogStatusFailure, targetRoleIDStr, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
		return domainErrors.ErrRoleNotFound
	}

	// TODO: Check if permission exists via a PermissionRepository if strict checking is needed.
	// For now, assume permissionID is valid or DB handles foreign key constraints.

	err = s.roleRepo.AssignPermissionToRole(ctx, roleID, permissionID)
	if err != nil {
		s.logger.Error("Failed to assign permission to role", zap.Error(err), zap.String("roleID", roleID), zap.String("permissionID", permissionID))
		auditDetails["error"] = "db role_permission_assign failed"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorID, "role_permission_assign", models.AuditLogStatusFailure, targetRoleIDStr, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
		return err
	}

	// Publish CloudEvent about permission assignment
	permissionAssignedPayload := models.RolePermissionChangedEvent{
		RoleID:          roleID,
		PermissionID:    permissionID,
		Action:          "assigned",
		ChangeTimestamp: time.Now(),
	}
	if actorID != nil {
		actorIDStr := actorID.String()
		permissionAssignedPayload.ChangedByUserID = &actorIDStr
	}
	subjectRolePermissionAssigned := roleID
	contentTypeJSON := "application/json"
	if errKafka := s.kafkaClient.PublishCloudEvent(
		ctx,
		s.cfg.Kafka.Producer.RolePermissionTopic,
		kafkaEvents.EventType(models.AuthRolePermissionChangedV1),
		&subjectRolePermissionAssigned,
		&contentTypeJSON,
		permissionAssignedPayload,
	); errKafka != nil {
		s.logger.Error("Failed to publish CloudEvent for role permission assigned", zap.Error(errKafka), zap.String("role_id", roleID), zap.String("permission_id", permissionID))
		if auditDetails == nil {
			auditDetails = make(map[string]interface{})
		}
		auditDetails["warning_cloudevent_publish"] = errKafka.Error()
	}
	s.auditLogRecorder.RecordEvent(ctx, actorID, "role_permission_assign", models.AuditLogStatusSuccess, targetRoleIDStr, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
	return nil
}

// RemovePermissionFromRole removes a permission from a role.
// actorID is the ID of the admin performing the action.
func (s *RoleService) RemovePermissionFromRole(ctx context.Context, roleID string, permissionID string, actorID *uuid.UUID) error {
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists {
			ipAddress = val
		}
		if val, exists := md["user-agent"]; exists {
			userAgent = val
		}
	}
	var auditDetails = make(map[string]interface{})
	targetRoleIDStr := &roleID
	auditDetails["permission_id_revoked"] = permissionID

	_, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		s.logger.Error("RemovePermissionFromRole: Role not found", zap.String("roleID", roleID), zap.Error(err))
		auditDetails["error"] = domainErrors.ErrRoleNotFound.Error()
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorID, "role_permission_revoke", models.AuditLogStatusFailure, targetRoleIDStr, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
		return domainErrors.ErrRoleNotFound
	}

	// TODO: Check if permission exists via a PermissionRepository if strict checking is needed.

	err = s.roleRepo.RemovePermissionFromRole(ctx, roleID, permissionID)
	if err != nil {
		s.logger.Error("Failed to remove permission from role", zap.Error(err), zap.String("roleID", roleID), zap.String("permissionID", permissionID))
		auditDetails["error"] = "db role_permission_revoke failed"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorID, "role_permission_revoke", models.AuditLogStatusFailure, targetRoleIDStr, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
		return err
	}

	// Publish CloudEvent about permission revocation
	permissionRevokedPayload := models.RolePermissionChangedEvent{
		RoleID:          roleID,
		PermissionID:    permissionID,
		Action:          "removed",
		ChangeTimestamp: time.Now(),
	}
	if actorID != nil {
		actorIDStr := actorID.String()
		permissionRevokedPayload.ChangedByUserID = &actorIDStr
	}
	subjectRolePermissionRevoked := roleID
	contentTypeJSON := "application/json"
	if errKafka := s.kafkaClient.PublishCloudEvent(
		ctx,
		s.cfg.Kafka.Producer.RolePermissionTopic,
		kafkaEvents.EventType(models.AuthRolePermissionChangedV1),
		&subjectRolePermissionRevoked,
		&contentTypeJSON,
		permissionRevokedPayload,
	); errKafka != nil {
		s.logger.Error("Failed to publish CloudEvent for role permission revoked", zap.Error(errKafka), zap.String("role_id", roleID), zap.String("permission_id", permissionID))
		if auditDetails == nil {
			auditDetails = make(map[string]interface{})
		}
		auditDetails["warning_cloudevent_publish"] = errKafka.Error()
	}
	s.auditLogRecorder.RecordEvent(ctx, actorID, "role_permission_revoke", models.AuditLogStatusSuccess, targetRoleIDStr, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
	return nil
}
