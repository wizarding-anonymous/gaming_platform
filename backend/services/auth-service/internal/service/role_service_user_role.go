// File: backend/services/auth-service/internal/service/role_service_user_role.go

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

// AssignRoleToUser назначает роль пользователю
func (s *RoleService) AssignRoleToUser(ctx context.Context, userID uuid.UUID, roleID string, adminUserID *uuid.UUID) error {
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
	targetUserID := &userID
	auditDetails["role_id_assigned"] = roleID

	_, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for role assignment", zap.Error(err), zap.String("user_id", userID.String()))
		auditDetails["error"] = domainErrors.ErrUserNotFound.Error()
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, adminUserID, "user_role_assign", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return domainErrors.ErrUserNotFound
	}

	_, err = s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		s.logger.Error("Failed to get role for assignment", zap.Error(err), zap.String("role_id", roleID))
		auditDetails["error"] = domainErrors.ErrRoleNotFound.Error()
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, adminUserID, "user_role_assign", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return domainErrors.ErrRoleNotFound
	}

	// Fetch old roles for event and audit log
	oldRoleIDs, errFetchOld := s.userRolesRepo.GetRoleIDsForUser(ctx, userID)
	if errFetchOld != nil {
		s.logger.Error("Failed to fetch old roles for event during AssignRoleToUser", zap.Error(errFetchOld), zap.String("userID", userID.String()))
		auditDetails["warning_fetch_old_roles"] = errFetchOld.Error()
	} else {
		auditDetails["old_role_ids"] = oldRoleIDs
	}

	// UserRolesRepository handles the assignment.
	err = s.userRolesRepo.AssignRoleToUser(ctx, userID, roleID, adminUserID)
	if err != nil {
		s.logger.Error("Failed to assign role to user", zap.Error(err), zap.String("user_id", userID.String()), zap.String("role_id", roleID))
		auditDetails["error"] = "db user_role_assign failed"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, adminUserID, "user_role_assign", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return err
	}

	// Fetch new roles for event and audit log
	newRoleIDs, errFetchNew := s.userRolesRepo.GetRoleIDsForUser(ctx, userID)
	if errFetchNew != nil {
		s.logger.Error("Failed to fetch new roles for event during AssignRoleToUser", zap.Error(errFetchNew), zap.String("userID", userID.String()))
		auditDetails["warning_fetch_new_roles"] = errFetchNew.Error()
	} else {
		auditDetails["new_role_ids"] = newRoleIDs
	}

	var changedByKafka *string // Renamed to avoid conflict with audit's actorID
	if adminUserID != nil {
		s := adminUserID.String()
		changedByKafka = &s
	}

	// Assuming UserRolesChangedEvent is in models package, or a specific payload for assigned event
	// For UserRoleAssignedV1, the payload might be UserRoleAssignedPayload
	// Let's assume a specific payload models.UserRoleAssignedPayload exists.
	// If not, models.UserRolesChangedEvent will be used.
	// For now, using generic event which is models.UserRolesChangedEvent as per current code.
	assignedEventPayload := models.UserRolesChangedEvent{ // Or models.UserRoleAssignedPayload
		UserID:          userID.String(),
		OldRoleIDs:      oldRoleIDs,
		NewRoleIDs:      newRoleIDs,
		ChangedByUserID: changedByKafka,
		ChangeTimestamp: time.Now(),
	}
	subjectUserRoleAssigned := userID.String()
	contentTypeJSON := "application/json"
	// Publish CloudEvent
	if errKafka := s.kafkaClient.PublishCloudEvent(
		ctx,
		s.cfg.Kafka.Producer.UserRoleTopic,
		kafkaEvents.EventType(models.AuthUserRoleAssignedV1), // eventType, cast to kafkaEvents.EventType
		// "auth-service", // source - removed
		&subjectUserRoleAssigned, // subject
		// "", // eventID - removed
		&contentTypeJSON,     // dataContentType
		assignedEventPayload, // dataPayload
	); errKafka != nil {
		s.logger.Error("Failed to publish CloudEvent for user role assigned", zap.Error(errKafka), zap.String("user_id", userID.String()), zap.String("role_id", roleID))
		if auditDetails == nil {
			auditDetails = make(map[string]interface{})
		} // Ensure auditDetails is not nil
		auditDetails["warning_cloudevent_publish"] = errKafka.Error()
	}

	s.auditLogRecorder.RecordEvent(ctx, adminUserID, "user_role_assign", models.AuditLogStatusSuccess, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	return nil
}

// RemoveRoleFromUser удаляет роль у пользователя
func (s *RoleService) RemoveRoleFromUser(ctx context.Context, userID uuid.UUID, roleID string, adminUserID *uuid.UUID) error {
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
	targetUserID := &userID
	auditDetails["role_id_revoked"] = roleID

	_, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for role removal", zap.Error(err), zap.String("user_id", userID.String()))
		auditDetails["error"] = domainErrors.ErrUserNotFound.Error()
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, adminUserID, "user_role_revoke", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return domainErrors.ErrUserNotFound
	}

	_, err = s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		s.logger.Error("Failed to get role for removal", zap.Error(err), zap.String("role_id", roleID))
		auditDetails["error"] = domainErrors.ErrRoleNotFound.Error()
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, adminUserID, "user_role_revoke", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return domainErrors.ErrRoleNotFound
	}

	oldRoleIDs, errFetchOld := s.userRolesRepo.GetRoleIDsForUser(ctx, userID)
	if errFetchOld != nil {
		s.logger.Error("Failed to fetch old roles for event during RemoveRoleFromUser", zap.Error(errFetchOld), zap.String("userID", userID.String()))
		auditDetails["warning_fetch_old_roles"] = errFetchOld.Error()
	} else {
		auditDetails["old_role_ids"] = oldRoleIDs
	}

	err = s.userRolesRepo.RemoveRoleFromUser(ctx, userID, roleID)
	if err != nil {
		s.logger.Error("Failed to remove role from user", zap.Error(err), zap.String("user_id", userID.String()), zap.String("role_id", roleID))
		auditDetails["error"] = "db user_role_revoke failed"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, adminUserID, "user_role_revoke", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return err
	}

	newRoleIDs, errFetchNew := s.userRolesRepo.GetRoleIDsForUser(ctx, userID)
	if errFetchNew != nil {
		s.logger.Error("Failed to fetch new roles for event during RemoveRoleFromUser", zap.Error(errFetchNew), zap.String("userID", userID.String()))
		auditDetails["warning_fetch_new_roles"] = errFetchNew.Error()
	} else {
		auditDetails["new_role_ids"] = newRoleIDs
	}

	var changedByKafka *string
	if adminUserID != nil {
		s := adminUserID.String()
		changedByKafka = &s
	}

	// Similar to assign, using generic models.UserRolesChangedEvent or a specific models.UserRoleRevokedPayload
	revokedEventPayload := models.UserRolesChangedEvent{ // Or models.UserRoleRevokedPayload
		UserID:          userID.String(),
		OldRoleIDs:      oldRoleIDs,
		NewRoleIDs:      newRoleIDs,
		ChangedByUserID: changedByKafka,
		ChangeTimestamp: time.Now(),
	}
	subjectUserRoleRevoked := userID.String()
	contentTypeJSON := "application/json"
	// Publish CloudEvent
	if errKafka := s.kafkaClient.PublishCloudEvent(
		ctx,
		s.cfg.Kafka.Producer.UserRoleTopic,
		kafkaEvents.EventType(models.AuthUserRoleRevokedV1), // eventType, cast to kafkaEvents.EventType
		// "auth-service", // source - removed
		&subjectUserRoleRevoked, // subject
		// "", // eventID - removed
		&contentTypeJSON,    // dataContentType
		revokedEventPayload, // dataPayload
	); errKafka != nil {
		s.logger.Error("Failed to publish CloudEvent for user role revoked", zap.Error(errKafka), zap.String("user_id", userID.String()), zap.String("role_id", roleID))
		if auditDetails == nil {
			auditDetails = make(map[string]interface{})
		} // Ensure auditDetails is not nil
		auditDetails["warning_cloudevent_publish"] = errKafka.Error()
	}

	s.auditLogRecorder.RecordEvent(ctx, adminUserID, "user_role_revoke", models.AuditLogStatusSuccess, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	return nil
}

// GetUserRoles получает роли пользователя
func (s *RoleService) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*models.Role, error) {
	// Проверка существования пользователя
	_, err := s.userRepo.FindByID(ctx, userID) // userRepo.FindByID now
	if err != nil {
		s.logger.Error("Failed to get user for roles retrieval", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, domainErrors.ErrUserNotFound
	}

	// This method should ideally use UserRolesRepository to get role IDs,
	// then RoleRepository to get role details for each ID.
	// For now, assuming s.roleRepo.GetUserRoles is adapted or this logic is more complex.
	// The existing RoleRepositoryPostgres.GetUserRoles fetches roles directly.
	roleIDs, err := s.userRolesRepo.GetRoleIDsForUser(ctx, userID) // Assuming s.userRolesRepo exists
	if err != nil {
		s.logger.Error("Failed to get role IDs for user", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, err
	}

	roles := make([]*models.Role, 0, len(roleIDs))
	for _, roleID := range roleIDs {
		role, err := s.roleRepo.GetByID(ctx, roleID)
		if err != nil {
			s.logger.Warn("Failed to get role detail for user's role ID", zap.String("roleID", roleID), zap.Error(err))
			// Decide whether to skip this role or return an error for the whole operation
			continue
		}
		roles = append(roles, role)
	}
	// The old s.roleRepo.GetUserRoles(ctx, userID) might be more direct if it joins correctly.
	// My refactored RoleRepository does not have GetUserRoles directly.
	// This highlights the need for UserRolesRepository to be properly injected and used.
	// For now, the above loop is a conceptual implementation.
	// Let's revert to the direct call if it's simpler and exists on the interface.
	// The RoleRepository interface does not have GetUserRoles.
	// The UserRolesRepository interface has GetRoleIDsForUser.
	// This means RoleService needs UserRolesRepository.

	// Corrected flow:
	// 1. Get role IDs from UserRolesRepository.
	// 2. For each role ID, get role details from RoleRepository.
	// (This is what the loop above does)
	if err != nil {
		s.logger.Error("Failed to get user roles", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, err
	}

	return roles, nil
}
