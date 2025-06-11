// File: backend/services/auth-service/internal/service/oauth_service.go
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain"
	domainService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka"
	repoInterfaces "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/repository/interfaces"
)

type OAuthService struct {
	cfg                 *config.Config
	logger              *zap.Logger
	userRepo            repoInterfaces.UserRepository
	externalAccountRepo repoInterfaces.ExternalAccountRepository
	sessionService      *SessionService
	tokenService        *TokenService // For creating platform tokens after successful OAuth
	transactionManager  domainService.TransactionManager
	kafkaClient         *kafkaEvents.Producer // For publishing events
	auditLogRecorder    domainService.AuditLogRecorder
	oauth2Configs       map[string]*oauth2.Config
}

func NewOAuthService(
	cfg *config.Config,
	logger *zap.Logger,
	userRepo repoInterfaces.UserRepository,
	externalAccountRepo repoInterfaces.ExternalAccountRepository,
	sessionService *SessionService,
	tokenService *TokenService,
	transactionManager domainService.TransactionManager,
	kafkaClient *kafkaEvents.Producer,
	auditLogRecorder domainService.AuditLogRecorder,
) *OAuthService {
	oauth2Configs := make(map[string]*oauth2.Config)
	for providerName, providerCfg := range cfg.OAuthProviders {
		oauth2Configs[providerName] = &oauth2.Config{
			ClientID:     providerCfg.ClientID,
			ClientSecret: providerCfg.ClientSecret,
			RedirectURL:  providerCfg.RedirectURL,
			Scopes:       providerCfg.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  providerCfg.AuthURL,
				TokenURL: providerCfg.TokenURL,
			},
		}
	}

	return &OAuthService{
		cfg:                 cfg,
		logger:              logger,
		userRepo:            userRepo,
		externalAccountRepo: externalAccountRepo,
		sessionService:      sessionService,
		tokenService:        tokenService,
		transactionManager:  transactionManager,
		kafkaClient:         kafkaClient,
		auditLogRecorder:    auditLogRecorder,
		oauth2Configs:       oauth2Configs,
	}
}

func (s *OAuthService) hashOAuthToken(token string) *string {
	if token == "" {
		return nil
	}
	hasher := sha256.New()
	hasher.Write([]byte(token))
	hashed := hex.EncodeToString(hasher.Sum(nil))
	return &hashed
}

// InitiateOAuth starts the OAuth 2.0 flow.
func (s *OAuthService) InitiateOAuth(ctx context.Context, provider string, w http.ResponseWriter, r *http.Request) (string, error) {
	oauthCfg, ok := s.oauth2Configs[provider]
	if !ok {
		s.logger.Warn("Invalid OAuth provider", zap.String("provider", provider))
		return "", fmt.Errorf("invalid provider: %s", provider)
	}

	// Generate a random state string for CSRF protection.
	state := uuid.New().String()
	// Store the state in a short-lived cookie or server-side session.
	// For simplicity, let's assume a cookie for now.
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		Secure:   r.TLS != nil, // Use Secure if served over HTTPS
	})

	// Redirect the user to the OAuth provider's authorization page.
	authURL := oauthCfg.AuthCodeURL(state)
	s.logger.Info("Redirecting to OAuth provider", zap.String("provider", provider), zap.String("url", authURL))
	return authURL, nil
}

// HandleOAuthCallback handles the callback from the OAuth provider.
// This function is complex and involves multiple steps:
// 1. Validate the state parameter to prevent CSRF attacks.
// 2. Exchange the authorization code for an access token.
// 3. Fetch user information from the provider using the access token.
// 4. Check if the user already exists in the system based on their email or provider ID.
// 5. If the user exists, link the external account if it's not already linked.
// 6. If the user does not exist, create a new user and link the external account.
// 7. Create a session for the user.
// 8. Publish relevant events (e.g., user registered, user logged in).
// 9. Record audit logs.
func (s *OAuthService) HandleOAuthCallback(ctx context.Context, provider, code, state string, r *http.Request) (*domain.User, *domain.Session, *domain.TokenPair, error) {
	// 1. Validate state
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		s.logger.Error("Failed to get oauth_state cookie", zap.Error(err))
		return nil, nil, nil, fmt.Errorf("missing oauth_state cookie: %w", err)
	}
	if stateCookie.Value != state {
		s.logger.Error("Invalid OAuth state", zap.String("expected", stateCookie.Value), zap.String("received", state))
		return nil, nil, nil, fmt.Errorf("invalid oauth state")
	}
	// Clear the state cookie
	http.SetCookie(r.Response.Writer, &http.Cookie{Name: "oauth_state", MaxAge: -1, Path: "/"})

	oauthCfg, ok := s.oauth2Configs[provider]
	if !ok {
		s.logger.Error("Invalid OAuth provider in callback", zap.String("provider", provider))
		return nil, nil, nil, fmt.Errorf("invalid provider: %s", provider)
	}

	// 2. Exchange code for token
	token, err := oauthCfg.Exchange(ctx, code)
	if err != nil {
		s.logger.Error("Failed to exchange OAuth code for token", zap.String("provider", provider), zap.Error(err))
		return nil, nil, nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// 3. Fetch user info (this part is provider-specific)
	// For simplicity, assuming a generic way to get UserInfo.
	// In a real application, you'd use provider-specific APIs.
	// Example: Google's UserInfo endpoint: https://www.googleapis.com/oauth2/v2/userinfo
	// This is a placeholder. You need to implement actual user info fetching.
	userInfo, err := s.fetchUserInfo(ctx, oauthCfg, token, provider)
	if err != nil {
		s.logger.Error("Failed to fetch user info from provider", zap.String("provider", provider), zap.Error(err))
		return nil, nil, nil, fmt.Errorf("failed to fetch user info: %w", err)
	}

	// Begin transaction
	tx, err := s.transactionManager.Begin(ctx)
	if err != nil {
		s.logger.Error("Failed to begin transaction", zap.Error(err))
		return nil, nil, nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			s.transactionManager.Rollback(tx)
			panic(p) // re-throw panic after Rollback
		} else if err != nil {
			s.transactionManager.Rollback(tx)
		} else {
			err = s.transactionManager.Commit(tx)
			if err != nil {
				s.logger.Error("Failed to commit transaction", zap.Error(err))
			}
		}
	}()

	userRepoTx := s.userRepo.WithTx(tx)
	externalAccountRepoTx := s.externalAccountRepo.WithTx(tx)

	// 4 & 5. Check if external account exists or if user with this email exists
	externalAccount, err := externalAccountRepoTx.GetByProviderUserID(ctx, provider, userInfo.ProviderUserID)
	if err != nil && err != domain.ErrNotFound {
		s.logger.Error("Error fetching external account", zap.Error(err))
		return nil, nil, nil, err
	}

	var user *domain.User
	if externalAccount != nil { // External account exists, fetch the associated user
		user, err = userRepoTx.GetByID(ctx, externalAccount.UserID)
		if err != nil {
			s.logger.Error("Failed to get user associated with external account", zap.String("userID", externalAccount.UserID.String()), zap.Error(err))
			return nil, nil, nil, err
		}
		s.logger.Info("User found via external account", zap.String("userID", user.ID.String()), zap.String("provider", provider))

		// Update tokens if they have changed
		hashedAccessToken := s.hashOAuthToken(token.AccessToken)
		hashedRefreshToken := s.hashOAuthToken(token.RefreshToken)

		needsUpdate := false
		if hashedAccessToken != nil && (externalAccount.AccessTokenHash == nil || *externalAccount.AccessTokenHash != *hashedAccessToken) {
			externalAccount.AccessTokenHash = hashedAccessToken
			needsUpdate = true
		}
		if hashedRefreshToken != nil && (externalAccount.RefreshTokenHash == nil || *externalAccount.RefreshTokenHash != *hashedRefreshToken) {
			externalAccount.RefreshTokenHash = hashedRefreshToken
			needsUpdate = true
		}
		if token.Expiry != externalAccount.TokenExpiry {
			externalAccount.TokenExpiry = token.Expiry
			needsUpdate = true
		}

		if needsUpdate {
			if err = externalAccountRepoTx.Update(ctx, externalAccount); err != nil {
				s.logger.Error("Failed to update external account with new tokens", zap.Error(err))
				return nil, nil, nil, err
			}
		}

	} else { // External account does not exist
		// Try to find user by email
		user, err = userRepoTx.GetByEmail(ctx, userInfo.Email)
		if err != nil && err != domain.ErrNotFound {
			s.logger.Error("Error fetching user by email", zap.Error(err))
			return nil, nil, nil, err
		}

		if user != nil { // User with this email exists, link new external account
			s.logger.Info("User found by email, linking new external account", zap.String("userID", user.ID.String()), zap.String("provider", provider))
			externalAccount = &domain.ExternalAccount{
				ID:               uuid.New(),
				UserID:           user.ID,
				Provider:         provider,
				ProviderUserID:   userInfo.ProviderUserID,
				Email:            userInfo.Email,
				Username:         &userInfo.Username,
				AccessTokenHash:  s.hashOAuthToken(token.AccessToken),
				RefreshTokenHash: s.hashOAuthToken(token.RefreshToken),
				TokenExpiry:      token.Expiry,
			}
			if err = externalAccountRepoTx.Create(ctx, externalAccount); err != nil {
				s.logger.Error("Failed to create external account for existing user", zap.Error(err))
				return nil, nil, nil, err
			}
			// Potentially publish an event: AccountLinked
			if s.kafkaClient != nil {
				event := kafkaEvents.AccountLinkedEvent{
					UserID:         user.ID.String(),
					Provider:       provider,
					ProviderUserID: userInfo.ProviderUserID,
				}
				if err := s.kafkaClient.PublishAccountLinkedEvent(ctx, event); err != nil {
					s.logger.Error("Failed to publish AccountLinkedEvent", zap.Error(err))
					// Non-critical error, continue
				}
			}
		} else { // No user found by email, create new user and new external account
			s.logger.Info("User not found, creating new user and external account", zap.String("email", userInfo.Email), zap.String("provider", provider))
			newUser := &domain.User{
				ID:        uuid.New(),
				Username:  userInfo.Username, // Or generate one if username is not from provider / can conflict
				Email:     userInfo.Email,
				IsActive:  true, // Auto-activate OAuth users or send verification if email is not trusted
				IsOAuth:   true,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			// If username is not guaranteed unique from provider, ensure uniqueness or handle conflicts
			// For now, assume it's acceptable or userInfo.Username is like "provider_username"
			if err = userRepoTx.Create(ctx, newUser); err != nil {
				s.logger.Error("Failed to create new user from OAuth", zap.Error(err))
				return nil, nil, nil, err
			}
			user = newUser

			externalAccount = &domain.ExternalAccount{
				ID:               uuid.New(),
				UserID:           user.ID,
				Provider:         provider,
				ProviderUserID:   userInfo.ProviderUserID,
				Email:            userInfo.Email,
				Username:         &userInfo.Username,
				AccessTokenHash:  s.hashOAuthToken(token.AccessToken),
				RefreshTokenHash: s.hashOAuthToken(token.RefreshToken),
				TokenExpiry:      token.Expiry,
			}
			if err = externalAccountRepoTx.Create(ctx, externalAccount); err != nil {
				s.logger.Error("Failed to create external account for new user", zap.Error(err))
				return nil, nil, nil, err
			}

			// Publish UserRegisteredEvent
			if s.kafkaClient != nil {
				event := kafkaEvents.UserRegisteredEvent{
					UserID:    user.ID.String(),
					Email:     user.Email,
					Username:  user.Username,
					AuthType:  "oauth_" + provider,
					Timestamp: time.Now(),
				}
				if err := s.kafkaClient.PublishUserRegisteredEvent(ctx, event); err != nil {
					s.logger.Error("Failed to publish UserRegisteredEvent", zap.Error(err))
					// Non-critical error, continue
				}
			}
		}
	}

	// 7. Create session
	session, err := s.sessionService.CreateSession(ctx, user.ID, r.UserAgent(), r.RemoteAddr)
	if err != nil {
		s.logger.Error("Failed to create session after OAuth login", zap.String("userID", user.ID.String()), zap.Error(err))
		return nil, nil, nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Create platform tokens
	tokenPair, err := s.tokenService.GenerateTokenPair(user.ID, session.ID)
	if err != nil {
		s.logger.Error("Failed to generate token pair after OAuth login", zap.String("userID", user.ID.String()), zap.Error(err))
		// Attempt to rollback session creation or mark session as invalid?
		// For now, return error, transaction will rollback user/externalAccount changes if any problem before commit.
		return nil, nil, nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// 8. Publish login event (even for new users, as they are now logged in)
	if s.kafkaClient != nil {
		loginEvent := kafkaEvents.UserLoggedInEvent{
			UserID:     user.ID.String(),
			SessionID:  session.ID.String(),
			LoginTime:  time.Now(),
			UserAgent:  r.UserAgent(),
			IPAddress:  r.RemoteAddr(),
			AuthMethod: "oauth_" + provider,
		}
		if err := s.kafkaClient.PublishUserLoggedInEvent(ctx, loginEvent); err != nil {
			s.logger.Error("Failed to publish UserLoggedInEvent", zap.Error(err))
			// Non-critical, proceed
		}
	}

	// 9. Record audit log
	if s.auditLogRecorder != nil {
		if err := s.auditLogRecorder.RecordEvent(ctx, tx, domainService.AuditLogEvent{ // Pass tx if RecordEvent can use it
			UserID:    &user.ID,
			Action:    "oauth_login",
			TargetID:  &user.ID,
			Details:   fmt.Sprintf("User %s logged in via OAuth provider %s", user.Email, provider),
			Timestamp: time.Now(),
		}); err != nil {
			s.logger.Error("Failed to record audit log for OAuth login", zap.Error(err))
			// Non-critical, proceed
		}
	}

	s.logger.Info("OAuth callback handled successfully", zap.String("userID", user.ID.String()), zap.String("provider", provider))
	return user, session, tokenPair, nil
}

// OAuthUserInfo represents standardized user information obtained from an OAuth provider.
type OAuthUserInfo struct {
	ProviderUserID string // Unique ID for the user on the provider's system
	Email          string
	Username       string // Optional: some providers might not give a username or it might not be suitable
	// Add other fields as needed, e.g., Name, ProfilePictureURL
}

// fetchUserInfo is a placeholder for provider-specific user info fetching.
// You MUST implement this for each OAuth provider you support.
func (s *OAuthService) fetchUserInfo(ctx context.Context, config *oauth2.Config, token *oauth2.Token, provider string) (*OAuthUserInfo, error) {
	// Example using Google's UserInfo endpoint.
	// THIS IS A SIMPLIFIED EXAMPLE AND MAY NEED ADJUSTMENT FOR ERROR HANDLING, SCOPES, ETC.
	if provider == "google" { // Assuming "google" is a key in your oauth2Configs
		client := config.Client(ctx, token)
		resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
		if err != nil {
			s.logger.Error("Failed to get user info from Google", zap.Error(err))
			return nil, fmt.Errorf("failed to get user info from %s: %w", provider, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			s.logger.Error("Error status from Google user info endpoint", zap.Int("status", resp.StatusCode))
			return nil, fmt.Errorf("error from %s user info endpoint: %s", provider, resp.Status)
		}

		var googleUser struct {
			ID    string `json:"id"`
			Email string `json:"email"`
			Name  string `json:"name"` // You might want to use this for username
		}
		if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
			s.logger.Error("Failed to decode user info from Google", zap.Error(err))
			return nil, fmt.Errorf("failed to decode user info from %s: %w", provider, err)
		}

		return &OAuthUserInfo{
			ProviderUserID: googleUser.ID,
			Email:          googleUser.Email,
			Username:       googleUser.Name, // Or generate/prompt for one
		}, nil
	}

	// Add other providers here (e.g., facebook, github)
	// if provider == "github" { ... }

	s.logger.Error("Unsupported provider for fetchUserInfo", zap.String("provider", provider))
	return nil, fmt.Errorf("unsupported provider: %s", provider)
}

// Make sure to add "encoding/json" and "time" to imports if not already there
// Also, the kafkaEvents.AccountLinkedEvent, UserRegisteredEvent, UserLoggedInEvent needs to be defined in the events package.
// The domainService.AuditLogEvent needs to be defined.
// The userRepo.WithTx(tx) and externalAccountRepo.WithTx(tx) methods are assumed to exist on your repository implementations.
// The transactionManager.Begin, Commit, Rollback methods are assumed to exist.
// The sessionService.CreateSession and tokenService.GenerateTokenPair are assumed to exist.
// The OAuthUserInfo struct and fetchUserInfo method are basic and need to be adapted for real providers.
// The HandleOAuthCallback assumes r.Response.Writer is available. In some frameworks, you might need to pass http.ResponseWriter explicitly.
// Error handling within HandleOAuthCallback, especially around transaction commit/rollback, is crucial.
// The User model's IsOAuth field is used.
// The ExternalAccount model stores OAuth tokens (hashed) and expiry.
// The hashOAuthToken method is added.
// The InitiateOAuth method uses cookies for state, ensure this is appropriate for your security model.
// The HandleOAuthCallback clears the state cookie.
// Logging is done using zap.Logger.
// cfg.OAuthProviders structure is assumed to be compatible.

// Placeholder for missing imports, will be added as needed by other files
// import (
//     "encoding/json"
//     "time"
// )
