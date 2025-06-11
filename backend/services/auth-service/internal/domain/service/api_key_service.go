// File: backend/services/auth-service/internal/domain/service/api_key_service.go
package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/entity"
	// Assuming models, eventModels, authDomainModels will be aliased or resolved to a common models package
	// For now, let's assume a primary 'models' package for event payloads and types,
	// and AuditLogStatus constants.
	"github.com/google/uuid"
	domainInterfaces "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/interfaces"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models" // For EventType, Payloads, Audit statuses
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository"
	kafkaPkg "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka" // Assuming this is the Sarama producer path
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/metrics"         // Added metrics import
)

const (
	apiKeyPrefix       = "pltfrm_sk_" // Platform Service Key prefix (example)
	apiKeySecretLength = 32           // Bytes for the secret part
	// RequiredPermissionsCtxKey is the context key for required permissions when authenticating an API key.
	RequiredPermissionsCtxKey = "required_permissions"
)

// APIKeyService defines the interface for managing API keys.
type APIKeyService interface {
	GenerateAndStoreAPIKey(ctx context.Context, userID string, name string, permissions []string, expiresAt *time.Time) (rawAPIKey string, storedKey *entity.APIKey, err error)
	ListUserAPIKeys(ctx context.Context, userID string) ([]*entity.APIKey, error)
	RevokeUserAPIKey(ctx context.Context, userID string, keyID string) error
	AuthenticateByAPIKey(ctx context.Context, rawAPIKey string) (userID string, permissions []string, keyID string, err error)
}

type apiKeyServiceImpl struct {
	apiKeyRepo       repository.APIKeyRepository
	passwordService  domainInterfaces.PasswordService // For hashing the secret part of the key
	auditLogRecorder AuditLogRecorder                 // Added
	kafkaProducer    *kafkaPkg.Producer               // Added for event publishing
}

// APIKeyServiceConfig holds dependencies for APIKeyService.
type APIKeyServiceConfig struct {
	APIKeyRepo       repository.APIKeyRepository
	PasswordService  domainInterfaces.PasswordService
	AuditLogRecorder AuditLogRecorder   // Added for audit logging
	KafkaProducer    *kafkaPkg.Producer // Added
}

// NewAPIKeyService creates a new apiKeyServiceImpl.
func NewAPIKeyService(cfg APIKeyServiceConfig) APIKeyService {
	return &apiKeyServiceImpl{
		apiKeyRepo:       cfg.APIKeyRepo,
		passwordService:  cfg.PasswordService,
		auditLogRecorder: cfg.AuditLogRecorder, // Added
		kafkaProducer:    cfg.KafkaProducer,    // Added
	}
}

func (s *apiKeyServiceImpl) GenerateAndStoreAPIKey(
	ctx context.Context, userID string, name string, permissions []string, expiresAt *time.Time,
) (string, *entity.APIKey, error) {
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
	auditDetails["key_name"] = name
	if expiresAt != nil {
		auditDetails["expires_at"] = expiresAt.String()
	}

	actorUserID, errParseActor := uuid.Parse(userID)
	var actorIDForLog *uuid.UUID
	if errParseActor == nil {
		actorIDForLog = &actorUserID
	} else {
		// Log warning if userID string is not a valid UUID for actor.
		// This implies userID in APIKey entity might not always be UUID.
		// For now, proceed with nil actorID for audit if parse fails.
		// logger.Warn("GenerateAndStoreAPIKey: Could not parse userID to UUID for audit actor", zap.String("userID", userID))
	}

	secretBytes := make([]byte, apiKeySecretLength)
	if _, err := rand.Read(secretBytes); err != nil {
		auditDetails["error"] = "failed to generate API key secret"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorIDForLog, "apikey_create", models.AuditLogStatusFailure, nil, models.AuditTargetTypeAPIKey, auditDetails, ipAddress, userAgent) // Assuming models.AuditLogStatusFailure
		return "", nil, fmt.Errorf("failed to generate API key secret: %w", err)
	}
	secretPart := base64.URLEncoding.EncodeToString(secretBytes)
	// prefix := apiKeyPrefix // Original global prefix, not used for raw key anymore

	newKeyID := uuid.NewString()                // Generate ID before creating struct for logging
	auditDetails["key_id_generated"] = newKeyID // Log the ID we intend to create

	// Generate unique prefix using the first 8 characters of the newKeyID
	if len(newKeyID) < 8 {
		// This case should ideally not happen with UUIDs, but good practice to check
		auditDetails["error"] = "failed to generate API key prefix due to short newKeyID"
		s.auditLogRecorder.RecordEvent(ctx, actorIDForLog, "apikey_create", models.AuditLogStatusFailure, nil, models.AuditTargetTypeAPIKey, auditDetails, ipAddress, userAgent)
		return "", nil, errors.New("failed to generate API key prefix: newKeyID is too short")
	}
	uniquePrefix := fmt.Sprintf("pltfrm_sk_%s", newKeyID[:8])
	rawAPIKey := uniquePrefix + "_" + secretPart

	hashedSecret, err := s.passwordService.HashPassword(secretPart)
	if err != nil {
		auditDetails["error"] = "failed to hash API key secret"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorIDForLog, "apikey_create", models.AuditLogStatusFailure, nil, models.AuditTargetTypeAPIKey, auditDetails, ipAddress, userAgent) // Assuming models.AuditLogStatusFailure
		return "", nil, fmt.Errorf("failed to hash API key secret: %w", err)
	}

	permissionsJSON, err := json.Marshal(permissions)
	if err != nil {
		auditDetails["error"] = "failed to marshal permissions to JSON"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorIDForLog, "apikey_create", models.AuditLogStatusFailure, nil, models.AuditTargetTypeAPIKey, auditDetails, ipAddress, userAgent) // Assuming models.AuditLogStatusFailure
		return "", nil, fmt.Errorf("failed to marshal permissions to JSON: %w", err)
	}

	now := time.Now()
	// newKeyID is already generated above to create uniquePrefix

	storedKey := &entity.APIKey{
		ID:          newKeyID,
		UserID:      userID,
		Name:        name,
		KeyPrefix:   uniquePrefix, // Store the unique prefix
		KeyHash:     hashedSecret,
		Permissions: permissionsJSON,
		ExpiresAt:   expiresAt,
		CreatedAt:   now,
		UpdatedAt:   &now,
	}

	if err := s.apiKeyRepo.Create(ctx, storedKey); err != nil {
		auditDetails["error"] = "failed to store API key in DB"
		auditDetails["details"] = err.Error()
		targetIDStr := &newKeyID                                                                                                                                                         // Use the generated ID as target even on failure
		s.auditLogRecorder.RecordEvent(ctx, actorIDForLog, "apikey_create", models.AuditLogStatusFailure, targetIDStr, models.AuditTargetTypeAPIKey, auditDetails, ipAddress, userAgent) // Assuming models.AuditLogStatusFailure
		return "", nil, fmt.Errorf("failed to store API key: %w", err)
	}

	targetIDSuccessStr := &storedKey.ID
	auditDetails["key_prefix_stored"] = storedKey.KeyPrefix

	// Publish CloudEvent
	// Assuming APIKeyCreatedPayload is in models package
	apiKeyCreatedPayload := models.APIKeyCreatedPayload{
		APIKeyID:  storedKey.ID,
		UserID:    storedKey.UserID, // UserID is string here
		Name:      storedKey.Name,
		KeyPrefix: storedKey.KeyPrefix,
		CreatedAt: storedKey.CreatedAt,
		ExpiresAt: storedKey.ExpiresAt,
	}
	if storedKey.Permissions != nil {
		var perms []string
		if errUnmarshal := json.Unmarshal(storedKey.Permissions, &perms); errUnmarshal == nil {
			apiKeyCreatedPayload.Permissions = perms
		} else {
			if auditDetails == nil {
				auditDetails = make(map[string]interface{})
			}
			auditDetails["warning_unmarshal_permissions_for_event"] = errUnmarshal.Error()
		}
	}

	subjectAPIKeyCreated := storedKey.UserID // UserID is string, used as subject
	contentTypeJSON := "application/json"    // Default content type
	// Assuming event type models.AuthAPIKeyCreatedV1 is kafkaPkg.EventType (string alias)
	// Publish event to the standard auth events topic.
	if err := s.kafkaProducer.PublishCloudEvent(
		ctx,
		kafkaPkg.AuthEventsTopic,
		kafkaPkg.EventType(models.AuthAPIKeyCreatedV1), // eventType
		&subjectAPIKeyCreated,                          // subject
		&contentTypeJSON,                               // dataContentType
		apiKeyCreatedPayload,                           // dataPayload
	); err != nil {
		if auditDetails == nil {
			auditDetails = make(map[string]interface{})
		}
		auditDetails["warning_cloudevent_publish"] = err.Error()
	}

	s.auditLogRecorder.RecordEvent(ctx, actorIDForLog, "apikey_create", models.AuditLogStatusSuccess, targetIDSuccessStr, models.AuditTargetTypeAPIKey, auditDetails, ipAddress, userAgent) // Assuming models.AuditLogStatusSuccess
	return rawAPIKey, storedKey, nil
}

func (s *apiKeyServiceImpl) ListUserAPIKeys(ctx context.Context, userID string) ([]*entity.APIKey, error) {
	keys, err := s.apiKeyRepo.ListByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list API keys for user %s: %w", userID, err)
	}
	// key_hash should already be excluded by the repository method for listings.
	return keys, nil
}

func (s *apiKeyServiceImpl) RevokeUserAPIKey(ctx context.Context, userID string, keyID string) error {
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
	targetKeyIDStr := &keyID

	actorUserID, errParseActor := uuid.Parse(userID)
	var actorIDForLog *uuid.UUID
	if errParseActor == nil {
		actorIDForLog = &actorUserID
	} else {
		// logger.Warn("RevokeUserAPIKey: Could not parse userID to UUID for audit actor", zap.String("userID", userID))
	}

	// The repository method Revoke(id, userID) already handles ownership check.
	err := s.apiKeyRepo.Revoke(ctx, keyID, userID)
	if err != nil {
		errReason := "failed to revoke API key"
		// Handle specific errors like "not found or not owned" if needed
		if strings.Contains(err.Error(), "API key not found") || strings.Contains(err.Error(), "not owned by user") {
			// Consider using a domain error type if available, e.g. entity.ErrNotFound or entity.ErrForbidden
			errReason = "API key not found or not owned by user"
		}
		auditDetails["error"] = errReason
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorIDForLog, "apikey_revoke", models.AuditLogStatusFailure, targetKeyIDStr, models.AuditTargetTypeAPIKey, auditDetails, ipAddress, userAgent) // Assuming models.AuditLogStatusFailure
		if errReason == "API key not found or not owned by user" {                                                                                                                          // Return a cleaner error if it's a known domain issue
			return errors.New(errReason) // Placeholder for entity.ErrAPIKeyNotFound or similar
		}
		return fmt.Errorf("failed to revoke API key %s for user %s: %w", keyID, userID, err)
	}

	// Publish CloudEvent
	// Assuming APIKeyRevokedPayload is in models package
	apiKeyRevokedPayload := models.APIKeyRevokedPayload{
		APIKeyID:  keyID,
		UserID:    userID, // UserID is string here
		RevokedAt: time.Now(),
	}
	subjectAPIKeyRevoked := userID // UserID is string, used as subject
	contentTypeJSON := "application/json"
	// Assuming event type models.AuthAPIKeyRevokedV1 is kafkaPkg.EventType (string alias)
	// Publish event to the standard auth events topic
	if err := s.kafkaProducer.PublishCloudEvent(
		ctx,
		kafkaPkg.AuthEventsTopic,
		kafkaPkg.EventType(models.AuthAPIKeyRevokedV1), // eventType
		&subjectAPIKeyRevoked,                          // subject
		&contentTypeJSON,                               // dataContentType
		apiKeyRevokedPayload,                           // dataPayload
	); err != nil {
		if auditDetails == nil {
			auditDetails = make(map[string]interface{})
		} // Ensure auditDetails is not nil
		auditDetails["warning_cloudevent_publish"] = err.Error()
	}

	s.auditLogRecorder.RecordEvent(ctx, actorIDForLog, "apikey_revoke", models.AuditLogStatusSuccess, targetKeyIDStr, models.AuditTargetTypeAPIKey, auditDetails, ipAddress, userAgent) // Assuming models.AuditLogStatusSuccess
	return nil
}

func (s *apiKeyServiceImpl) AuthenticateByAPIKey(
	ctx context.Context, rawAPIKey string,
) (userID string, permissions []string, keyID string, err error) {
	ipAddress := "unknown"
	userAgent := "unknown" // UserAgent might not be available for API key auth typically
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists {
			ipAddress = val
		}
		if val, exists := md["user-agent"]; exists {
			userAgent = val
		}
	}
	var auditDetails = make(map[string]interface{})
	var parsedPrefixForAudit string // For logging on failure
	var actorIDForLog *uuid.UUID
	var targetKeyIDStr *string

	// Original logic for parsing and validating key structure (simplified for brevity in this diff search block)
	// This part needs to be accurate to the actual file. Assuming the "Re-evaluating" part is current.
	lastUnderscore := strings.LastIndex(rawAPIKey, "_")
	if lastUnderscore == -1 || lastUnderscore == len(rawAPIKey)-1 {
		err = errors.New("invalid API key format: missing delimiter or secret")
		auditDetails["error_reason"] = err.Error()
		auditDetails["provided_key_snippet"] = truncateKey(rawAPIKey, 10)                                                                                                    // Use helper
		s.auditLogRecorder.RecordEvent(ctx, nil, "apikey_auth_failure", models.AuditLogStatusFailure, nil, models.AuditTargetTypeAPIKey, auditDetails, ipAddress, userAgent) // Assuming models.AuditLogStatusFailure
		metrics.APIKeyValidationAttemptsTotal.WithLabelValues("failure_invalid_key").Inc()
		return "", nil, "", err
	}
	parsedPrefix := rawAPIKey[:lastUnderscore]
	parsedSecretPart := rawAPIKey[lastUnderscore+1:]
	parsedPrefixForAudit = parsedPrefix

	if parsedPrefix == "" || parsedSecretPart == "" {
		err = errors.New("invalid API key format: prefix or secret part is empty")
		auditDetails["error_reason"] = err.Error()
		auditDetails["provided_prefix"] = parsedPrefixForAudit
		s.auditLogRecorder.RecordEvent(ctx, nil, "apikey_auth_failure", models.AuditLogStatusFailure, nil, models.AuditTargetTypeAPIKey, auditDetails, ipAddress, userAgent) // Assuming models.AuditLogStatusFailure
		metrics.APIKeyValidationAttemptsTotal.WithLabelValues("failure_invalid_key").Inc()
		return "", nil, "", err
	}

	apiKeyEntity, err := s.apiKeyRepo.FindByKeyPrefix(ctx, parsedPrefix)
	if err != nil {
		// This includes "not found"
		finalErr := errors.New("API key not found or invalid prefix")
		auditDetails["error_reason"] = finalErr.Error()
		auditDetails["provided_prefix"] = parsedPrefixForAudit
		auditDetails["db_error_details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, nil, "apikey_auth_failure", models.AuditLogStatusFailure, nil, models.AuditTargetTypeAPIKey, auditDetails, ipAddress, userAgent) // Assuming models.AuditLogStatusFailure
		metrics.APIKeyValidationAttemptsTotal.WithLabelValues("failure_invalid_key").Inc()
		return "", nil, "", finalErr
	}

	// From here, we have apiKeyEntity, so we can set targetKeyIDStr and potentially actorIDForLog
	targetKeyIDStr = &apiKeyEntity.ID
	if parsedActorUUID, parseErr := uuid.Parse(apiKeyEntity.UserID); parseErr == nil {
		actorIDForLog = &parsedActorUUID
	}

	if apiKeyEntity.RevokedAt != nil {
		err = errors.New("API key has been revoked")
		auditDetails["error_reason"] = err.Error()
		auditDetails["key_id"] = apiKeyEntity.ID
		s.auditLogRecorder.RecordEvent(ctx, actorIDForLog, "apikey_auth_failure", models.AuditLogStatusFailure, targetKeyIDStr, models.AuditTargetTypeAPIKey, auditDetails, ipAddress, userAgent) // Assuming models.AuditLogStatusFailure
		metrics.APIKeyValidationAttemptsTotal.WithLabelValues("failure_revoked").Inc()
		return "", nil, "", err
	}
	if apiKeyEntity.ExpiresAt != nil && apiKeyEntity.ExpiresAt.Before(time.Now()) {
		err = errors.New("API key has expired")
		auditDetails["error_reason"] = err.Error()
		auditDetails["key_id"] = apiKeyEntity.ID
		auditDetails["expires_at"] = apiKeyEntity.ExpiresAt.String()
		s.auditLogRecorder.RecordEvent(ctx, actorIDForLog, "apikey_auth_failure", models.AuditLogStatusFailure, targetKeyIDStr, models.AuditTargetTypeAPIKey, auditDetails, ipAddress, userAgent) // Assuming models.AuditLogStatusFailure
		metrics.APIKeyValidationAttemptsTotal.WithLabelValues("failure_expired").Inc()
		return "", nil, "", err
	}

	match, err := s.passwordService.CheckPasswordHash(parsedSecretPart, apiKeyEntity.KeyHash)
	if err != nil {
		finalErr := errors.New("error verifying API key secret")
		auditDetails["error_reason"] = finalErr.Error()
		auditDetails["key_id"] = apiKeyEntity.ID
		auditDetails["internal_error_details"] = err.Error()                                                                                                                                      // Original error
		s.auditLogRecorder.RecordEvent(ctx, actorIDForLog, "apikey_auth_failure", models.AuditLogStatusFailure, targetKeyIDStr, models.AuditTargetTypeAPIKey, auditDetails, ipAddress, userAgent) // Assuming models.AuditLogStatusFailure
		metrics.APIKeyValidationAttemptsTotal.WithLabelValues("failure_invalid_key").Inc()                                                                                                        // Error during hash check implies invalid key/secret
		return "", nil, "", finalErr
	}
	if !match {
		err = errors.New("invalid API key secret")
		auditDetails["error_reason"] = err.Error()
		auditDetails["key_id"] = apiKeyEntity.ID
		s.auditLogRecorder.RecordEvent(ctx, actorIDForLog, "apikey_auth_failure", models.AuditLogStatusFailure, targetKeyIDStr, models.AuditTargetTypeAPIKey, auditDetails, ipAddress, userAgent) // Assuming models.AuditLogStatusFailure
		metrics.APIKeyValidationAttemptsTotal.WithLabelValues("failure_invalid_key").Inc()
		return "", nil, "", err
	}

	if errUpdate := s.apiKeyRepo.UpdateLastUsedAt(ctx, apiKeyEntity.ID); errUpdate != nil {
		// Log error, but proceed with successful auth
		// logger.Error("Failed to update last_used_at for API key", zap.Error(errUpdate), zap.String("apiKeyID", apiKeyEntity.ID))
		auditDetails["warning_update_last_used"] = errUpdate.Error() // Add to details for success log
	}

	var perms []string
	if apiKeyEntity.Permissions != nil {
		if errUnmarshal := json.Unmarshal(apiKeyEntity.Permissions, &perms); errUnmarshal != nil {
			// Log error, but proceed, maybe with empty permissions
			// logger.Error("Failed to unmarshal API key permissions", zap.Error(errUnmarshal), zap.String("apiKeyID", apiKeyEntity.ID))
			auditDetails["warning_unmarshal_permissions"] = errUnmarshal.Error()
			// Decide if this is a hard failure for the auth itself. If perms are critical, it might be.
			// For now, logging success as auth itself (key valid) passed.
			s.auditLogRecorder.RecordEvent(ctx, actorIDForLog, "apikey_auth_success", models.AuditLogStatusSuccess, targetKeyIDStr, models.AuditTargetTypeAPIKey, auditDetails, ipAddress, userAgent) // Assuming models.AuditLogStatusSuccess
			// If permissions are essential for the key to be considered "valid" for a request, this might be a "failure_no_permission" case.
			// However, the current logic returns the key as valid but with potentially empty permissions.
			// For now, let's assume a key is valid if the secret matches, and permission checks happen later.
			// If unmarshalling permissions fails, it's more of a data integrity issue for that key's permissions.
			// This doesn't fit neatly into the requested metric labels without more context on how permissions affect "validity".
			// Sticking to "success" for the key authentication itself.
			metrics.APIKeyValidationAttemptsTotal.WithLabelValues("success").Inc()
			return apiKeyEntity.UserID, []string{}, apiKeyEntity.ID, fmt.Errorf("failed to unmarshal key permissions: %w", errUnmarshal)
		}
	}
	// Check required permissions from context, if provided.
	if reqPerms, ok := ctx.Value(RequiredPermissionsCtxKey).([]string); ok && len(reqPerms) > 0 {
		permSet := make(map[string]struct{}, len(perms))
		for _, p := range perms {
			permSet[p] = struct{}{}
		}
		for _, rp := range reqPerms {
			if _, has := permSet[rp]; !has {
				err = errors.New("insufficient permissions for API key")
				auditDetails["error_reason"] = err.Error()
				auditDetails["missing_permission"] = rp
				s.auditLogRecorder.RecordEvent(ctx, actorIDForLog, "apikey_auth_failure", models.AuditLogStatusFailure, targetKeyIDStr, models.AuditTargetTypeAPIKey, auditDetails, ipAddress, userAgent)
				metrics.APIKeyValidationAttemptsTotal.WithLabelValues("failure_no_permission").Inc()
				return "", nil, apiKeyEntity.ID, err
			}
		}
	}

	auditDetails["permissions_granted_count"] = len(perms)                                                                                                                                    // Example of adding success detail
	s.auditLogRecorder.RecordEvent(ctx, actorIDForLog, "apikey_auth_success", models.AuditLogStatusSuccess, targetKeyIDStr, models.AuditTargetTypeAPIKey, auditDetails, ipAddress, userAgent) // Assuming models.AuditLogStatusSuccess
	metrics.APIKeyValidationAttemptsTotal.WithLabelValues("success").Inc()
	return apiKeyEntity.UserID, perms, apiKeyEntity.ID, nil
}

// Helper function to truncate key for logging, avoiding full secret exposure.
func truncateKey(key string, visibleLen int) string {
	if len(key) > visibleLen {
		return key[:visibleLen] + "..."
	}
	return key
}

var _ APIKeyService = (*apiKeyServiceImpl)(nil)
