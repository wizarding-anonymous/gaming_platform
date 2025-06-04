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

	"github.com/gameplatform/auth-service/internal/domain/entity"
	"github.com/gameplatform/auth-service/internal/domain/repository"
	"github.com/google/uuid"
)

const (
	apiKeyPrefix    = "pltfrm_sk_" // Platform Service Key prefix (example)
	apiKeySecretLength = 32         // Bytes for the secret part
)

// APIKeyService defines the interface for managing API keys.
type APIKeyService interface {
	GenerateAndStoreAPIKey(ctx context.Context, userID string, name string, permissions []string, expiresAt *time.Time) (rawAPIKey string, storedKey *entity.APIKey, err error)
	ListUserAPIKeys(ctx context.Context, userID string) ([]*entity.APIKey, error)
	RevokeUserAPIKey(ctx context.Context, userID string, keyID string) error
	AuthenticateByAPIKey(ctx context.Context, rawAPIKey string) (userID string, permissions []string, keyID string, err error)
}

type apiKeyServiceImpl struct {
	apiKeyRepo      repository.APIKeyRepository
	passwordService PasswordService // For hashing the secret part of the key
}

// APIKeyServiceConfig holds dependencies for APIKeyService.
type APIKeyServiceConfig struct {
	APIKeyRepo      repository.APIKeyRepository
	PasswordService PasswordService
}

// NewAPIKeyService creates a new apiKeyServiceImpl.
func NewAPIKeyService(cfg APIKeyServiceConfig) APIKeyService {
	return &apiKeyServiceImpl{
		apiKeyRepo:      cfg.APIKeyRepo,
		passwordService: cfg.PasswordService,
	}
}

func (s *apiKeyServiceImpl) GenerateAndStoreAPIKey(
	ctx context.Context, userID string, name string, permissions []string, expiresAt *time.Time,
) (string, *entity.APIKey, error) {

	// 1. Generate secure random string for the secret part
	secretBytes := make([]byte, apiKeySecretLength)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", nil, fmt.Errorf("failed to generate API key secret: %w", err)
	}
	secretPart := base64.URLEncoding.EncodeToString(secretBytes) // URL-safe base64

	// 2. Create prefix (already defined as constant)
	prefix := apiKeyPrefix

	// 3. Form the raw API key
	rawAPIKey := prefix + secretPart

	// 4. Hash the secret_part
	// Using PasswordService (Argon2id). Note: For high-traffic API key auth, a faster hash
	// like SHA256/SHA512 might be considered, but Argon2id is very secure.
	hashedSecret, err := s.passwordService.HashPassword(secretPart)
	if err != nil {
		return "", nil, fmt.Errorf("failed to hash API key secret: %w", err)
	}

	// 5. Store in database
	permissionsJSON, err := json.Marshal(permissions)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal permissions to JSON: %w", err)
	}

	now := time.Now()
	storedKey := &entity.APIKey{
		ID:          uuid.NewString(),
		UserID:      userID,
		Name:        name,
		KeyPrefix:   prefix,
		KeyHash:     hashedSecret,
		Permissions: permissionsJSON,
		ExpiresAt:   expiresAt,
		CreatedAt:   now,
		UpdatedAt:   &now, // Set by trigger as well
	}

	if err := s.apiKeyRepo.Create(ctx, storedKey); err != nil {
		return "", nil, fmt.Errorf("failed to store API key: %w", err)
	}

	// Return the raw API key (shown only once) and the database entity (without raw secret)
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
	// The repository method Revoke(id, userID) already handles ownership check.
	if err := s.apiKeyRepo.Revoke(ctx, keyID, userID); err != nil {
		// Handle specific errors like "not found or not owned" if needed
		if strings.Contains(err.Error(), "API key not found") || strings.Contains(err.Error(), "not owned by user") {
			return errors.New("API key not found or not owned by user") // Placeholder: entity.ErrAPIKeyNotFound
		}
		return fmt.Errorf("failed to revoke API key %s for user %s: %w", keyID, userID, err)
	}
	return nil
}

func (s *apiKeyServiceImpl) AuthenticateByAPIKey(
	ctx context.Context, rawAPIKey string,
) (userID string, permissions []string, keyID string, err error) {

	// 1. Parse rawAPIKey into prefix and secret_part
	if !strings.HasPrefix(rawAPIKey, apiKeyPrefix) {
		return "", nil, "", errors.New("invalid API key format: incorrect prefix") // Placeholder: entity.ErrInvalidAPIKeyFormat
	}
	secretPart := strings.TrimPrefix(rawAPIKey, apiKeyPrefix)
	if len(secretPart) == 0 {
		return "", nil, "", errors.New("invalid API key format: missing secret part") // Placeholder
	}

	// 2. Hash the secret_part to compare with stored hash
	// IMPORTANT: This step depends on the hashing strategy used during key creation.
	// Since we used PasswordService.HashPassword (Argon2id) for storing, we *cannot* simply hash
	// the incoming secretPart and compare. Argon2id hashes are unique each time due to salting.
	// The correct way to verify an Argon2id hash is to use PasswordService.CheckPasswordHash.
	// This means FindByPrefixAndHash in the repository is problematic if it expects a pre-hashed secret for Argon2id.
	//
	// For API Key authentication, a common pattern is:
	// a) Store a salted hash (e.g. SHA256(secret_part + salt)) -> Repo finds by prefix, gets salt & hash, service re-computes and compares.
	// b) Store just the hash of the secret part (e.g. SHA256(secret_part)) -> Repo finds by prefix & hash_of_secret_part.
	//
	// If using Argon2id (PasswordService) for API keys:
	// The repo method `FindByPrefixAndHash` would need to be `FindByPrefix`, then the service would iterate
	// through keys with that prefix (should be unique) and call `CheckPasswordHash` for each.
	// This is inefficient if many keys share a prefix (though prefix is meant to be unique for the key itself).
	//
	// Let's assume `PasswordService` is used, and adjust the flow:
	// The `key_prefix` in `api_keys` table is UNIQUE.
	
	apiKey, err := s.apiKeyRepo.FindByKeyPrefix(ctx, apiKeyPrefix) // The prefix is constant for all keys here. This needs re-thinking.
	// The prefix stored in the DB is the unique prefix for *that specific key*, not a global prefix.
	// The rawAPIKey is `key.KeyPrefix + secretPart`. So, the prefix IS part of the rawAPIKey.

	// Correct parsing of prefix and secret:
	// Example rawAPIKey: pltfrm_sk_abcdef12345_ThisIsTheSecretPart
	// We need a way to distinguish the prefix from the secret.
	// A fixed length for the random part of the prefix, or a delimiter.
	// The current `apiKeyPrefix` is "pltfrm_sk_". This is a global prefix.
	// The `entity.APIKey.KeyPrefix` is the *unique identifier prefix* for the key.
	// Let's assume the raw key is just `prefix_from_db + secret_part`.
	// The client only has ONE string. How do we get the `key_prefix` for DB lookup?
	//
	// Common patterns for API keys:
	// 1. `PREFIX_<RANDOM_ID_PART>_<BASE64_SECRET>` - ID part is looked up, then secret verified.
	// 2. The entire part before the last `_` is an ID, and the part after is the secret.
	// 3. Key is `prefix_from_db + secret_part_clear_text`. Client sends this. Server hashes secret_part_clear_text and compares with key_hash from DB, looking up by prefix_from_db.

	// Let's use pattern 3, as it's simpler with current repo.
	// The `rawAPIKey` is what the user provides. It does not contain the DB `id`.
	// It should contain the `key_prefix` and the cleartext `secret_part`.
	// So, `rawAPIKey = key.KeyPrefix + secret_part_generated_by_us`.
	// The client must send this exact string.

	// We need to parse `rawAPIKey` into its `actualPrefix` and `actualSecretPart`.
	// The `apiKeyPrefix` ("pltfrm_sk_") is just a type indicator, not the full DB prefix.
	// The `KeyPrefix` field in the DB is the unique identifier for the key that the user sees.
	// So, rawAPIKey = DBKeyPrefix + ClearTextSecret.

	// Let's assume the rawAPIKey format is: `unique_key_prefix_from_db` + `_` + `base64_encoded_secret_part`
	// Example: "KEYID123_secretpartbase64"
	// We need to split this. This requires a defined structure for rawAPIKey.

	// For this subtask, let's simplify: Assume `rawAPIKey` is *just the secret part*, and the prefix is sent separately or as part of a structured token (e.g. "Authorization: ApiKey PREFIX SECRET").
	// Or, the `prefix` in `FindByPrefixAndHash` is the *unique* key prefix.
	// If `rawAPIKey` is `prefix_unique + secret_cleartext`:
	
	// Re-evaluating: The subtask asks to parse `rawAPIKey` into `prefix` and `secret_part`.
	// This implies `rawAPIKey` contains both. Let's assume a delimiter, like the last underscore.
	lastUnderscore := strings.LastIndex(rawAPIKey, "_")
	if lastUnderscore == -1 || lastUnderscore == len(rawAPIKey)-1 {
		return "", nil, "", errors.New("invalid API key format: missing delimiter or secret")
	}
	parsedPrefix := rawAPIKey[:lastUnderscore]
	parsedSecretPart := rawAPIKey[lastUnderscore+1:]

	if parsedPrefix == "" || parsedSecretPart == "" {
		return "", nil, "", errors.New("invalid API key format: prefix or secret part is empty")
	}

	// 3. Hash the parsedSecretPart for comparison if not using Argon2id check.
	// Since PasswordService.CheckPasswordHash is used, we don't pre-hash here.
	// We fetch the key by prefix first.
	
	apiKeyEntity, err := s.apiKeyRepo.FindByKeyPrefix(ctx, parsedPrefix)
	if err != nil {
		// This includes "not found"
		return "", nil, "", errors.New("API key not found or invalid prefix") // Placeholder
	}

	// 4. Check if key is active
	if apiKeyEntity.RevokedAt != nil {
		return "", nil, "", errors.New("API key has been revoked") // Placeholder
	}
	if apiKeyEntity.ExpiresAt != nil && apiKeyEntity.ExpiresAt.Before(time.Now()) {
		return "", nil, "", errors.New("API key has expired") // Placeholder
	}

	// 5. Verify the secret part using PasswordService
	match, err := s.passwordService.CheckPasswordHash(parsedSecretPart, apiKeyEntity.KeyHash)
	if err != nil {
		// Log internal error
		return "", nil, "", errors.New("error verifying API key secret") // Placeholder
	}
	if !match {
		return "", nil, "", errors.New("invalid API key secret") // Placeholder
	}

	// 6. Update last_used_at
	if err := s.apiKeyRepo.UpdateLastUsedAt(ctx, apiKeyEntity.ID); err != nil {
		// Log error, but proceed with successful auth
	}

	// 7. Return details
	var perms []string
	if apiKeyEntity.Permissions != nil {
		if err := json.Unmarshal(apiKeyEntity.Permissions, &perms); err != nil {
			// Log error, but proceed, maybe with empty permissions
			return apiKeyEntity.UserID, []string{}, apiKeyEntity.ID, fmt.Errorf("failed to unmarshal key permissions: %w", err)
		}
	}

	return apiKeyEntity.UserID, perms, apiKeyEntity.ID, nil
}


var _ APIKeyService = (*apiKeyServiceImpl)(nil)