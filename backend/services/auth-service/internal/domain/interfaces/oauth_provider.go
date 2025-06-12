// File: backend/services/auth-service/internal/domain/interfaces/oauth_provider.go
package interfaces

import (
	"context"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
)

// OAuthProvider abstracts interactions with a specific OAuth provider.
type OAuthProvider interface {
	// GetAuthURL returns the authorization URL for the provider using the given state parameter.
	GetAuthURL(state string) (string, error)

	// ExchangeCode exchanges the authorization code for provider tokens.
	ExchangeCode(ctx context.Context, code string) (*models.OAuthToken, error)

	// FetchUserInfo retrieves user information using the provided tokens.
	FetchUserInfo(ctx context.Context, token *models.OAuthToken) (*models.OAuthUserInfo, error)
}
