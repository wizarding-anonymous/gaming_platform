// File: backend/services/auth-service/internal/service/telegram_auth_service.go
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	domainInterfaces "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/interfaces"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	eventModels "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models" // Using existing alias for event payloads
	domainService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka"
	repoInterfaces "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/repository/interfaces"
)

const TelegramProviderName = "telegram"

type TelegramAuthService struct {
	cfg                 *config.Config
	logger              *zap.Logger
	userRepo            repoInterfaces.UserRepository
	externalAccountRepo repoInterfaces.ExternalAccountRepository
	sessionService      *SessionService
	tokenService        *TokenService
	telegramVerifier    domainInterfaces.TelegramVerifierService
	transactionManager  domainService.TransactionManager
	kafkaClient         *kafkaEvents.Producer
	auditLogRecorder    domainService.AuditLogRecorder
}

func NewTelegramAuthService(
	cfg *config.Config,
	logger *zap.Logger,
	userRepo repoInterfaces.UserRepository,
	externalAccountRepo repoInterfaces.ExternalAccountRepository,
	sessionService *SessionService,
	tokenService *TokenService,
	telegramVerifier domainInterfaces.TelegramVerifierService,
	transactionManager domainService.TransactionManager,
	kafkaClient *kafkaEvents.Producer,
	auditLogRecorder domainService.AuditLogRecorder,
) *TelegramAuthService {
	return &TelegramAuthService{
		cfg:                 cfg,
		logger:              logger,
		userRepo:            userRepo,
		externalAccountRepo: externalAccountRepo,
		sessionService:      sessionService,
		tokenService:        tokenService,
		telegramVerifier:    telegramVerifier,
		transactionManager:  transactionManager,
		kafkaClient:         kafkaClient,
		auditLogRecorder:    auditLogRecorder,
	}
}

func (s *TelegramAuthService) AuthenticateViaTelegram(ctx context.Context, telegramData models.TelegramAuthData, ipAddress string, userAgent string) (*models.User, *models.TokenPair, error) {
	verifiedProfile, err := s.telegramVerifier.Verify(ctx, telegramData)
	if err != nil {
		s.logger.Warn("Telegram authentication failed: verification error", zap.Error(err), zap.Int64("telegram_id", telegramData.ID))
		// It's important that domainInterfaces.TelegramVerifierService.Verify returns a typed error
		// that can be checked here, e.g. if it's domainErrors.ErrTelegramAuthInvalidHash
		// For now, wrapping it generally.
		return nil, nil, fmt.Errorf("%w: %v", domainErrors.ErrTelegramAuthFailed, err)
	}
	s.logger.Info("Telegram data verified successfully", zap.Int64("telegram_id", verifiedProfile.ID))

	externalUserID := strconv.FormatInt(verifiedProfile.ID, 10)

	var appUser *models.User
	var session *models.Session
	var tokenPair *models.TokenPair
	var isNewUser bool = false

	txCtx, err := s.transactionManager.Begin(ctx)
	if err != nil {
		s.logger.Error("Failed to begin transaction for Telegram auth", zap.Error(err))
		return nil, nil, domainErrors.ErrInternal
	}
	defer func() {
		if p := recover(); p != nil {
			s.transactionManager.Rollback(txCtx)
			panic(p)
		} else if err != nil {
			s.logger.Warn("Rolling back transaction due to error", zap.Error(err))
			s.transactionManager.Rollback(txCtx)
		} else {
			s.logger.Info("Committing transaction for Telegram auth")
			commitErr := s.transactionManager.Commit(txCtx)
			if commitErr != nil {
				s.logger.Error("Failed to commit transaction for Telegram auth", zap.Error(commitErr))
				// Set error for the main function return
				err = domainErrors.ErrInternal
				// Nullify results as commit failed
				appUser = nil
				tokenPair = nil
			}
		}
	}()

	userRepoTx := s.userRepo.WithTx(txCtx)
	externalAccountRepoTx := s.externalAccountRepo.WithTx(txCtx)

	existingExternalAccount, err := externalAccountRepoTx.FindByProviderAndExternalID(txCtx, TelegramProviderName, externalUserID)
	if err != nil && !errors.Is(err, domainErrors.ErrNotFound) {
		s.logger.Error("Failed to query for existing Telegram external account", zap.Error(err), zap.String("external_user_id", externalUserID))
		return nil, nil, domainErrors.ErrInternal
	}

	profileDataBytes, marshalErr := json.Marshal(verifiedProfile)
	if marshalErr != nil {
		s.logger.Error("Failed to marshal Telegram profile data", zap.Error(marshalErr), zap.String("external_user_id", externalUserID))
		return nil, nil, domainErrors.ErrInternal
	}
	profileDataRaw := json.RawMessage(profileDataBytes)

	if existingExternalAccount != nil { // ExternalAccount exists
		s.logger.Info("Existing Telegram external account found", zap.String("external_account_id", existingExternalAccount.ID.String()), zap.String("user_id", existingExternalAccount.UserID.String()))
		appUser, err = userRepoTx.FindByID(txCtx, existingExternalAccount.UserID)
		if err != nil {
			if errors.Is(err, domainErrors.ErrUserNotFound) {
				s.logger.Error("User associated with existing Telegram external account not found", zap.Error(err), zap.String("user_id", existingExternalAccount.UserID.String()))
				return nil, nil, domainErrors.ErrUserNotFound // Or a more specific "consistency error"
			}
			s.logger.Error("Failed to fetch user for existing Telegram external account", zap.Error(err), zap.String("user_id", existingExternalAccount.UserID.String()))
			return nil, nil, domainErrors.ErrInternal
		}

		existingExternalAccount.ProfileData = profileDataRaw
		existingExternalAccount.UpdatedAt = time.Now().UTC()
		if err = externalAccountRepoTx.Update(txCtx, existingExternalAccount); err != nil {
			s.logger.Error("Failed to update Telegram external account profile data", zap.Error(err), zap.String("external_account_id", existingExternalAccount.ID.String()))
			return nil, nil, domainErrors.ErrInternal
		}
		s.logger.Info("Telegram external account updated", zap.String("external_account_id", existingExternalAccount.ID.String()))
	} else { // ExternalAccount does not exist
		isNewUser = true // Potentially a new user, or linking to an existing user not yet implemented here
		s.logger.Info("No existing Telegram external account found, creating new user and account", zap.String("external_user_id", externalUserID))

		username := verifiedProfile.Username
		if username == "" {
			username = fmt.Sprintf("%s_%s", TelegramProviderName, externalUserID)
		}
		// TODO: Check for username collisions and handle appropriately (e.g., append random suffix)

		var photoURLPtr *string
		if verifiedProfile.PhotoURL != "" {
			photoURLPtr = &verifiedProfile.PhotoURL
		}

		newUser := &models.User{
			ID:              uuid.New(),
			Username:        username,
			Email:           nil, // No email from Telegram
			PasswordHash:    "",  // No password for Telegram-only users
			Status:          models.UserStatusActive,
			EmailVerifiedAt: nil,
			ProfileImageURL: photoURLPtr,
			CreatedAt:       time.Now().UTC(),
			UpdatedAt:       time.Now().UTC(),
			IsOAuth:         true, // Treat as OAuth-like external auth
		}

		if err = userRepoTx.Create(txCtx, newUser); err != nil {
			s.logger.Error("Failed to create new user for Telegram auth", zap.Error(err), zap.String("username", newUser.Username))
			return nil, nil, domainErrors.ErrInternal
		}
		appUser = newUser
		s.logger.Info("New user created for Telegram auth", zap.String("user_id", appUser.ID.String()), zap.String("username", appUser.Username))

		// Publish UserRegisteredEvent
		if s.kafkaClient != nil {
			regSource := "telegram"
			userRegisteredPayload := eventModels.UserRegisteredPayload{
				UserID:                appUser.ID.String(),
				Username:              appUser.Username,
				Email:                 "", // No email from Telegram
				RegistrationTimestamp: appUser.CreatedAt,
				RegistrationMethod:    "telegram",
				RegistrationSource:    &regSource,
				IPAddress:             &ipAddress,
				UserAgent:             &userAgent,
			}
			subjectUserRegistered := appUser.ID.String()
			contentType := "application/json"
			if pubErr := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, kafkaEvents.EventType(eventModels.AuthUserRegisteredV1), &subjectUserRegistered, &contentType, userRegisteredPayload); pubErr != nil {
				s.logger.Error("Failed to publish UserRegisteredEvent for Telegram user", zap.Error(pubErr), zap.String("user_id", appUser.ID.String()))
				// Non-critical, continue
			}
		}

		newExternalAccount := &models.ExternalAccount{
			ID:             uuid.New(),
			UserID:         appUser.ID,
			Provider:       TelegramProviderName,
			ExternalUserID: externalUserID,
			ProfileData:    profileDataRaw,
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
		}
		if err = externalAccountRepoTx.Create(txCtx, newExternalAccount); err != nil {
			s.logger.Error("Failed to create Telegram external account", zap.Error(err), zap.String("user_id", appUser.ID.String()))
			return nil, nil, domainErrors.ErrInternal
		}
		s.logger.Info("Telegram external account created", zap.String("external_account_id", newExternalAccount.ID.String()))

		// Publish AccountLinkedEvent
		if s.kafkaClient != nil {
			event := kafkaEvents.AccountLinkedEvent{ // Assuming kafkaEvents.AccountLinkedEvent exists
				UserID:         appUser.ID.String(),
				Provider:       TelegramProviderName,
				ProviderUserID: externalUserID,
				// Timestamp: time.Now(), // Add if the event schema supports it
			}
			if pubErr := s.kafkaClient.PublishAccountLinkedEvent(ctx, event); pubErr != nil { // Assuming specific publisher method
				s.logger.Error("Failed to publish AccountLinkedEvent for Telegram user", zap.Error(pubErr), zap.String("user_id", appUser.ID.String()))
				// Non-critical, continue
			}
		}
	}

	// Check user status
	if appUser.Status == models.UserStatusBlocked {
		s.logger.Warn("Attempt to login with blocked user via Telegram", zap.String("user_id", appUser.ID.String()))
		err = domainErrors.ErrUserBlocked // Set error for deferred rollback
		return nil, nil, err
	}
	if appUser.Status == models.UserStatusDeleted {
		s.logger.Warn("Attempt to login with deleted user via Telegram", zap.String("user_id", appUser.ID.String()))
		err = domainErrors.ErrUserDeleted // Set error for deferred rollback
		return nil, nil, err
	}
	if appUser.Status == models.UserStatusPendingVerification && appUser.Email != nil && *appUser.Email != "" {
		// This case should ideally not happen for pure Telegram login if email is not collected.
		// If email were collected and required verification, this would be relevant.
		s.logger.Warn("User pending email verification attempted Telegram login", zap.String("user_id", appUser.ID.String()))
		err = domainErrors.ErrEmailNotVerified
		return nil, nil, err
	}

	session, err = s.sessionService.CreateSession(ctx, appUser.ID, userAgent, ipAddress)
	if err != nil {
		s.logger.Error("Failed to create session for Telegram user", zap.Error(err), zap.String("user_id", appUser.ID.String()))
		return nil, nil, fmt.Errorf("session creation failed: %w", err) // err will be caught by defer
	}

	tokenPair, err = s.tokenService.CreateTokenPairWithSession(ctx, appUser, session.ID)
	if err != nil {
		s.logger.Error("Failed to create token pair for Telegram user", zap.Error(err), zap.String("user_id", appUser.ID.String()))
		return nil, nil, fmt.Errorf("token pair creation failed: %w", err) // err will be caught by defer
	}

	// If we reach here, transaction will be committed by defer unless an error was set above.
	// Publish login event (after successful commit, ideally)
	// For now, publishing before commit to simplify defer logic, but Kafka events should be idempotent or handled carefully with transactions.
	if s.kafkaClient != nil {
		loginMethod := TelegramProviderName
		loginSuccessPayload := eventModels.UserLoginSuccessPayload{
			UserID:         appUser.ID.String(),
			SessionID:      session.ID.String(),
			LoginTimestamp: time.Now().UTC(),
			IPAddress:      ipAddress,
			UserAgent:      userAgent,
			LoginMethod:    &loginMethod,
		}
		subjectUserIDLogin := appUser.ID.String()
		contentTypeJSONLogin := "application/json"
		if pubErr := s.kafkaClient.PublishCloudEvent(
			ctx, // Use original context, not txCtx for Kafka
			s.cfg.Kafka.Producer.Topic,
			kafkaEvents.EventType(eventModels.AuthUserLoginSuccessV1),
			&subjectUserIDLogin,
			&contentTypeJSONLogin,
			loginSuccessPayload,
		); pubErr != nil {
			s.logger.Error("Failed to publish UserLoginSuccessEvent for Telegram user", zap.Error(pubErr), zap.String("user_id", appUser.ID.String()))
			// Non-critical for login flow itself
		}
	}

	// Record audit log (also ideally after commit)
	var userIDForAudit *uuid.UUID
	if appUser != nil {
		uid := appUser.ID
		userIDForAudit = &uid
	}
	auditAction := "user_telegram_login"
	if isNewUser {
		auditAction = "user_telegram_register_login"
	}

	auditDetails := map[string]interface{}{
		"telegram_user_id": verifiedProfile.ID,
		"ip_address":       ipAddress,
		"user_agent":       userAgent,
	}
	// Pass txCtx to audit log recorder if it needs to participate in the transaction.
	// If audit log is external and shouldn't fail the main transaction, call it after commit.
	// For now, assuming it can be part of the transaction or is handled correctly by the recorder.
	s.auditLogRecorder.RecordEvent(txCtx, userIDForAudit, auditAction, models.AuditLogStatusSuccess, userIDForAudit, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)

	s.logger.Info("Telegram authentication successful", zap.String("user_id", appUser.ID.String()), zap.Bool("is_new_user", isNewUser))
	return appUser, tokenPair, nil // err will be nil if commit succeeds
}
