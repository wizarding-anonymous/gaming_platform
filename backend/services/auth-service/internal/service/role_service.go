// File: internal/service/role_service.go

package service

import (
	"context"
	"time"

	"errors" // Added for errors.Is
	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors" // Added for domainErrors.ErrRoleNotFound
	domainService "github.com/your-org/auth-service/internal/domain/service" // Added for domainService.AuditLogRecorder
	"github.com/your-org/auth-service/internal/repository/interfaces"
	"github.com/your-org/auth-service/internal/utils/kafka"
	"go.uber.org/zap"
)

// RoleService предоставляет методы для работы с ролями
type RoleService struct {
	roleRepo      interfaces.RoleRepository
	userRepo      interfaces.UserRepository // Still needed for validating user existence in some flows
	userRolesRepo interfaces.UserRolesRepository // Added
	kafkaClient   *kafka.Client
	logger        *zap.Logger
	auditLogRecorder domainService.AuditLogRecorder // Added for audit logging
}

// NewRoleService создает новый экземпляр RoleService
func NewRoleService(
	roleRepo interfaces.RoleRepository,
	userRepo interfaces.UserRepository,
	userRolesRepo interfaces.UserRolesRepository, // Added
	kafkaClient *kafka.Client,
	logger *zap.Logger,
	auditLogRecorder domainService.AuditLogRecorder, // Added
) *RoleService {
	return &RoleService{
		roleRepo:      roleRepo,
		userRepo:      userRepo,
		userRolesRepo: userRolesRepo, // Added
		kafkaClient:   kafkaClient,
		logger:        logger,
		auditLogRecorder: auditLogRecorder, // Added
	}
}

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
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
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
		if role.ID != "" { targetRoleID = &role.ID}
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
			RoleID:      createdRoleForEvent.ID,
			Name:        createdRoleForEvent.Name,
			CreatedAt:   createdRoleForEvent.CreatedAt,
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
		// TODO: Determine correct topic
		if errKafka := s.kafkaProducer.PublishCloudEvent(
			ctx,
			"auth-events", // topic
			string(models.AuthRoleCreatedV1), // eventType, changed from eventModels
			"auth-service", // source
			&subjectRoleCreated, // subject
			"", // eventID
			&contentTypeJSON, // dataContentType
			roleCreatedPayload, // dataPayload
		); errKafka != nil {
			s.logger.Error("Failed to publish CloudEvent for role created", zap.Error(errKafka), zap.String("role_id", role.ID))
			if auditDetails == nil { auditDetails = make(map[string]interface{}) }
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
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
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
			RoleID:    updatedRoleForEvent.ID,
			UpdatedAt: updatedRoleForEvent.UpdatedAt,
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
		// TODO: Determine correct topic
		if errKafka := s.kafkaProducer.PublishCloudEvent(
			ctx,
			"auth-events", // topic
			string(models.AuthRoleUpdatedV1), // eventType, changed from eventModels
			"auth-service", // source
			&subjectRoleUpdated, // subject
			"", // eventID
			&contentTypeJSON, // dataContentType
			roleUpdatePayload, // dataPayload
		); errKafka != nil {
			s.logger.Error("Failed to publish CloudEvent for role updated", zap.Error(errKafka), zap.String("role_id", role.ID))
			if auditDetails == nil { auditDetails = make(map[string]interface{}) }
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
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
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
	// TODO: Determine correct topic
	if errKafka := s.kafkaProducer.PublishCloudEvent(
		ctx,
		"auth-events", // topic
		string(models.AuthRoleDeletedV1), // eventType, changed from eventModels
		"auth-service", // source
		&subjectRoleDeleted, // subject
		"", // eventID
		&contentTypeJSON, // dataContentType
		roleDeletedPayload, // dataPayload
	); errKafka != nil {
		s.logger.Error("Failed to publish CloudEvent for role deleted", zap.Error(errKafka), zap.String("role_id", role.ID))
		if auditDetails == nil { auditDetails = make(map[string]interface{}) }
		auditDetails["warning_cloudevent_publish"] = errKafka.Error()
	}

	s.auditLogRecorder.RecordEvent(ctx, actorID, "role_delete", models.AuditLogStatusSuccess, targetRoleID, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
	return nil
}

// AssignRoleToUser назначает роль пользователю
func (s *RoleService) AssignRoleToUser(ctx context.Context, userID uuid.UUID, roleID string, adminUserID *uuid.UUID) error {
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
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
	// TODO: Determine correct topic, using placeholder "auth-events" for now. Should be from cfg.
	if errKafka := s.kafkaProducer.PublishCloudEvent(
		ctx,
		"auth-events", // topic
		string(models.AuthUserRoleAssignedV1), // eventType, changed from eventModels
		"auth-service", // source
		&subjectUserRoleAssigned, // subject
		"", // eventID
		&contentTypeJSON, // dataContentType
		assignedEventPayload, // dataPayload
	); errKafka != nil {
		s.logger.Error("Failed to publish CloudEvent for user role assigned", zap.Error(errKafka), zap.String("user_id", userID.String()), zap.String("role_id", roleID))
		if auditDetails == nil { auditDetails = make(map[string]interface{}) } // Ensure auditDetails is not nil
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
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
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
	// TODO: Determine correct topic
	if errKafka := s.kafkaProducer.PublishCloudEvent(
		ctx,
		"auth-events", // topic
		string(models.AuthUserRoleRevokedV1), // eventType, changed from eventModels
		"auth-service", // source
		&subjectUserRoleRevoked, // subject
		"", // eventID
		&contentTypeJSON, // dataContentType
		revokedEventPayload, // dataPayload
	); errKafka != nil {
		s.logger.Error("Failed to publish CloudEvent for user role revoked", zap.Error(errKafka), zap.String("user_id", userID.String()), zap.String("role_id", roleID))
		if auditDetails == nil { auditDetails = make(map[string]interface{}) } // Ensure auditDetails is not nil
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

// AssignPermissionToRole assigns a permission to a role.
// actorID is the ID of the admin performing the action.
func (s *RoleService) AssignPermissionToRole(ctx context.Context, roleID string, permissionID string, actorID *uuid.UUID) error {
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
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

	// TODO: Publish event: auth.role.permissions_changed (RoleID, PermissionID, "assigned", ChangedBy, Timestamp)
	s.auditLogRecorder.RecordEvent(ctx, actorID, "role_permission_assign", models.AuditLogStatusSuccess, targetRoleIDStr, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
	return nil
}

// RemovePermissionFromRole removes a permission from a role.
// actorID is the ID of the admin performing the action.
func (s *RoleService) RemovePermissionFromRole(ctx context.Context, roleID string, permissionID string, actorID *uuid.UUID) error {
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
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

	// TODO: Publish event: auth.role.permissions_changed (RoleID, PermissionID, "removed", ChangedBy, Timestamp)
	s.auditLogRecorder.RecordEvent(ctx, actorID, "role_permission_revoke", models.AuditLogStatusSuccess, targetRoleIDStr, models.AuditTargetTypeRole, auditDetails, ipAddress, userAgent)
	return nil
}
