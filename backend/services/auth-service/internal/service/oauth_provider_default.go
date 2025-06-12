// File: backend/services/auth-service/internal/service/oauth_provider_default.go
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"

	domainInterfaces "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/interfaces"
	domainModels "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
)

// DefaultOAuthProvider is a basic implementation of OAuthProvider using oauth2.Config.
type DefaultOAuthProvider struct {
	Config           *oauth2.Config
	UserInfoEndpoint string
}

func NewDefaultOAuthProvider(cfg *oauth2.Config, userInfoEndpoint string) domainInterfaces.OAuthProvider {
	return &DefaultOAuthProvider{Config: cfg, UserInfoEndpoint: userInfoEndpoint}
}

func (p *DefaultOAuthProvider) GetAuthURL(state string) (string, error) {
	return p.Config.AuthCodeURL(state), nil
}

func (p *DefaultOAuthProvider) ExchangeCode(ctx context.Context, code string) (*domainModels.OAuthToken, error) {
	token, err := p.Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}
	return &domainModels.OAuthToken{AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, Expiry: token.Expiry}, nil
}

func (p *DefaultOAuthProvider) FetchUserInfo(ctx context.Context, tok *domainModels.OAuthToken) (*domainModels.OAuthUserInfo, error) {
	client := p.Config.Client(ctx, &oauth2.Token{AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken, Expiry: tok.Expiry})
	resp, err := client.Get(p.UserInfoEndpoint + "?access_token=" + tok.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("user info request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info status: %s", resp.Status)
	}
	var tmp struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tmp); err != nil {
		return nil, fmt.Errorf("decode user info: %w", err)
	}
	return &domainModels.OAuthUserInfo{ProviderUserID: tmp.ID, Email: tmp.Email, Username: tmp.Name}, nil
}
