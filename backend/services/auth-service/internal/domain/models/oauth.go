// File: backend/services/auth-service/internal/domain/models/oauth.go
package models

import "time"

// OAuthToken represents OAuth provider tokens in a service-agnostic format.
type OAuthToken struct {
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
}

// OAuthUserInfo holds basic user information returned by an OAuth provider.
type OAuthUserInfo struct {
	ProviderUserID string
	Email          string
	Username       string
}
