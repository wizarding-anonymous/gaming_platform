// File: backend/services/auth-service/internal/service/role_service_crud.go

package service

import (
	"context"
	"time"

	"errors"
	"github.com/google/uuid"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	kafkaEvents "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka"
	"go.uber.org/zap"
)

// GetRoles получает список всех ролей
func (s *RoleService) GetRoles(ctx context.Context) ([]*models.Role, error) {
	roles, err := s.roleRepo.GetAll(ctx)
	if err != nil {
		s.logger.Error("Failed to get roles", zap.Error(err))
		return nil, err
	}
	return roles, nil
}

// GetRoleByID получает роль по ID
func (s *RoleService) GetRoleByID(ctx context.Context, id string) (*models.Role, error) { // Changed id to string
	role, err := s.roleRepo.GetByID(ctx, id) // roleRepo.GetByID now expects string
	if err != nil {
		s.logger.Error("Failed to get role by ID", zap.Error(err), zap.String("role_id", id))
		return nil, err
	}
	return role, nil
}

// GetRoleByName получает роль по имени
func (s *RoleService) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	role, err := s.roleRepo.GetByName(ctx, name)
	if err != nil {
		s.logger.Error("Failed to get role by name", zap.Error(err), zap.String("role_name", name))
		return nil, err
	}
	return role, nil
}

// CreateRole создает новую роль
// actorID is the ID of the admin performing the action.
func (s *RoleService) CreateRole(ctx context.Context, req models.CreateRoleRequest, actorID *uuid.UUID) (*models.Role, error) {
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
	auditDetails["role_id_provided"] = req.ID // req.ID is string
	auditDetails["role_name"] = req.Name

	// Проверка, существует ли роль с таким именем
	existingRole, err := s.roleRepo.GetByName(ctx, req.Name)
	if err == nil && existingRole != nil {
		currentErr := models.ErrRoleNameExists
		auditDetails["error"] = currentErr.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorID, "role_create", models.AuditLogStatusFailure, &existingRole.ID, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
		return nil, currentErr
	}
	// If error is not ErrRoleNotFound, then it's an unexpected DB error during check
	if err != nil && !errors.Is(err, domainErrors.ErrRoleNotFound) { // Assuming ErrRoleNotFound exists in domainErrors
		s.logger.Error("Error checking role name existence", zap.Error(err))
		auditDetails["error"] = "db error checking role name"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorID, "role_create", models.AuditLogStatusFailure, nil, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
		return nil, err
	}

	role := &models.Role{
		ID:          req.ID,
		Name:        req.Name,
		Description: req.Description,
	}

	err = s.roleRepo.Create(ctx, role)
	if err != nil {
		s.logger.Error("Failed to create role", zap.Error(err))
		auditDetails["error"] = "db role creation failed"
		auditDetails["details"] = err.Error()
		// Use role.ID (string) directly as targetID if available, even if creation failed mid-way or ID was client provided.
		var targetRoleID *string
		if role.ID != "" {
			targetRoleID = &role.ID
		}
		s.auditLogRecorder.RecordEvent(ctx, actorID, "role_create", models.AuditLogStatusFailure, targetRoleID, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
		return nil, err
	}
	targetRoleIDSuccess := &role.ID // role.ID is string

	createdRoleForEvent, errFetch := s.roleRepo.GetByID(ctx, role.ID)
	if errFetch != nil {
		s.logger.Warn("Could not fetch role after creation for event details", zap.String("roleID", role.ID), zap.Error(errFetch))
		// Non-critical for role creation itself, log as warning in audit.
		auditDetails["warning_fetch_for_event"] = errFetch.Error()
	} else {
		// Map to new payload
		// Assuming RoleCreatedPayload is now in models package
		roleCreatedPayload := models.RoleCreatedPayload{
			RoleID:    createdRoleForEvent.ID,
			Name:      createdRoleForEvent.Name,
			CreatedAt: createdRoleForEvent.CreatedAt,
		}
		if createdRoleForEvent.Description != "" { // Handle if description can be empty
			roleCreatedPayload.Description = &createdRoleForEvent.Description
		}
		if actorID != nil {
			actorIDStr := actorID.String()
			roleCreatedPayload.ActorID = &actorIDStr
		}

		subjectRoleCreated := createdRoleForEvent.ID // ID is string
		contentTypeJSON := "application/json"
		if errKafka := s.kafkaClient.PublishCloudEvent( // Publish to Kafka
			ctx,
			s.cfg.Kafka.Producer.RoleTopic,
			kafkaEvents.EventType(models.AuthRoleCreatedV1), // eventType, cast to kafkaEvents.EventType
			// "auth-service", // source - removed
			&subjectRoleCreated, // subject
			// "", // eventID - removed
			&contentTypeJSON,   // dataContentType
			roleCreatedPayload, // dataPayload
		); errKafka != nil {
			s.logger.Error("Failed to publish CloudEvent for role created", zap.Error(errKafka), zap.String("role_id", role.ID))
			if auditDetails == nil {
				auditDetails = make(map[string]interface{})
			}
			auditDetails["warning_cloudevent_publish"] = errKafka.Error()
		}
	}

	s.auditLogRecorder.RecordEvent(ctx, actorID, "role_create", models.AuditLogStatusSuccess, targetRoleIDSuccess, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
	return role, nil
}

// UpdateRole обновляет информацию о роли
// actorID is the ID of the admin performing the action.
func (s *RoleService) UpdateRole(ctx context.Context, id string, req models.UpdateRoleRequest, actorID *uuid.UUID) (*models.Role, error) {
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
	var changedFields []string
	targetRoleID := &id // id is string

	role, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		s.logger.Error("Failed to get role for update", zap.Error(err), zap.String("role_id", id))
		auditDetails["error"] = "role not found for update"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorID, "role_update", models.AuditLogStatusFailure, targetRoleID, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
		return nil, err
	}

	if req.Name != nil && *req.Name != role.Name {
		existingRole, errName := s.roleRepo.GetByName(ctx, *req.Name)
		if errName == nil && existingRole != nil && existingRole.ID != id {
			currentErr := domainErrors.ErrDuplicateValue // Using ErrDuplicateValue as role name should be unique
			auditDetails["error"] = currentErr.Error()
			auditDetails["attempted_name"] = *req.Name
			s.auditLogRecorder.RecordEvent(ctx, actorID, "role_update", models.AuditLogStatusFailure, targetRoleID, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
			return nil, currentErr
		}
		if errName != nil && !errors.Is(errName, domainErrors.ErrRoleNotFound) {
			s.logger.Error("Error checking new role name existence", zap.Error(errName))
			auditDetails["error"] = "db error checking new role name"
			auditDetails["details"] = errName.Error()
			s.auditLogRecorder.RecordEvent(ctx, actorID, "role_update", models.AuditLogStatusFailure, targetRoleID, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
			return nil, errName
		}
		role.Name = *req.Name
		changedFields = append(changedFields, "name")
	}

	if req.Description != nil && *req.Description != role.Description { // Check if description actually changed
		role.Description = *req.Description
		changedFields = append(changedFields, "description")
	}

	if len(changedFields) == 0 {
		auditDetails["info"] = "no fields to update"
		s.auditLogRecorder.RecordEvent(ctx, actorID, "role_update", models.AuditLogStatusSuccess, targetRoleID, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
		return role, nil
	}
	auditDetails["changed_fields"] = changedFields
	// UpdatedAt handled by DB trigger

	err = s.roleRepo.Update(ctx, role)
	if err != nil {
		s.logger.Error("Failed to update role", zap.Error(err), zap.String("role_id", id))
		auditDetails["error"] = "db role update failed"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorID, "role_update", models.AuditLogStatusFailure, targetRoleID, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
		return nil, err
	}

	updatedRoleForEvent, errFetchUpdate := s.roleRepo.GetByID(ctx, id)
	if errFetchUpdate != nil {
		s.logger.Warn("Could not fetch role after update for event details", zap.String("roleID", id), zap.Error(errFetchUpdate))
		auditDetails["warning_fetch_for_event"] = errFetchUpdate.Error()
	} else {
		// Map to new CloudEvent payload
		// Assuming RoleUpdatedPayload is now in models package
		roleUpdatePayload := models.RoleUpdatedPayload{
			RoleID:        updatedRoleForEvent.ID,
			UpdatedAt:     updatedRoleForEvent.UpdatedAt,
			ChangedFields: changedFields, // This was captured earlier in the method
		}
		// Only include Name and Description in payload if they were actually part of the update request
		if req.Name != nil {
			roleUpdatePayload.Name = req.Name
		}
		if req.Description != nil {
			roleUpdatePayload.Description = req.Description
		}
		if actorID != nil {
			actorIDStr := actorID.String()
			roleUpdatePayload.ActorID = &actorIDStr
		}
		subjectRoleUpdated := updatedRoleForEvent.ID // ID is string
		contentTypeJSON := "application/json"
		if errKafka := s.kafkaClient.PublishCloudEvent(
			ctx,
			s.cfg.Kafka.Producer.RoleTopic,
			kafkaEvents.EventType(models.AuthRoleUpdatedV1), // eventType, cast to kafkaEvents.EventType
			// "auth-service", // source - removed
			&subjectRoleUpdated, // subject
			// "", // eventID - removed
			&contentTypeJSON,  // dataContentType
			roleUpdatePayload, // dataPayload
		); errKafka != nil {
			s.logger.Error("Failed to publish CloudEvent for role updated", zap.Error(errKafka), zap.String("role_id", role.ID))
			if auditDetails == nil {
				auditDetails = make(map[string]interface{})
			}
			auditDetails["warning_cloudevent_publish"] = errKafka.Error()
		}
	}

	s.auditLogRecorder.RecordEvent(ctx, actorID, "role_update", models.AuditLogStatusSuccess, targetRoleID, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
	return role, nil
}

// DeleteRole удаляет роль
// actorID is the ID of the admin performing the action.
func (s *RoleService) DeleteRole(ctx context.Context, id string, actorID *uuid.UUID) error {
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
	targetRoleID := &id // id is string

	role, err := s.roleRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, domainErrors.ErrRoleNotFound) {
			auditDetails["info"] = "role already not found"
			s.auditLogRecorder.RecordEvent(ctx, actorID, "role_delete", models.AuditLogStatusSuccess, targetRoleID, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
			return nil // Idempotent delete
		}
		s.logger.Error("Failed to get role for deletion", zap.Error(err), zap.String("role_id", id))
		auditDetails["error"] = "failed to get role for deletion"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorID, "role_delete", models.AuditLogStatusFailure, targetRoleID, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
		return err
	}
	auditDetails["deleted_role_name"] = role.Name // Capture name before it's gone

	err = s.roleRepo.Delete(ctx, id)
	if err != nil {
		s.logger.Error("Failed to delete role", zap.Error(err), zap.String("role_id", id))
		auditDetails["error"] = "db role delete failed"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorID, "role_delete", models.AuditLogStatusFailure, targetRoleID, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
		return err
	}

	deletedAt := time.Now()
	// Assuming RoleDeletedPayload is now in models package
	roleDeletedPayload := models.RoleDeletedPayload{
		RoleID:    role.ID,
		DeletedAt: deletedAt,
	}
	if actorID != nil {
		actorIDStr := actorID.String()
		roleDeletedPayload.ActorID = &actorIDStr
	}

	subjectRoleDeleted := role.ID // ID is string
	contentTypeJSON := "application/json"
	if errKafka := s.kafkaClient.PublishCloudEvent(
		ctx,
		s.cfg.Kafka.Producer.RoleTopic,
		kafkaEvents.EventType(models.AuthRoleDeletedV1), // eventType, cast to kafkaEvents.EventType
		// "auth-service", // source - removed
		&subjectRoleDeleted, // subject
		// "", // eventID - removed
		&contentTypeJSON,   // dataContentType
		roleDeletedPayload, // dataPayload
	); errKafka != nil {
		s.logger.Error("Failed to publish CloudEvent for role deleted", zap.Error(errKafka), zap.String("role_id", role.ID))
		if auditDetails == nil {
			auditDetails = make(map[string]interface{})
		}
		auditDetails["warning_cloudevent_publish"] = errKafka.Error()
	}

	s.auditLogRecorder.RecordEvent(ctx, actorID, "role_delete", models.AuditLogStatusSuccess, targetRoleID, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
	return nil
}
