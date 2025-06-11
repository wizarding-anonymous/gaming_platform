// File: backend/services/auth-service/internal/service/auth_service_oauth.go
package service

// OAuthService returns the underlying OAuthService.
// This can be used by handlers to call OAuth specific methods.
func (s *AuthService) OAuthService() *OAuthService {
	return s.oauthService
}

// TelegramAuthService returns the underlying TelegramAuthService.
func (s *AuthService) TelegramAuthService() *TelegramAuthService {
	return s.telegramAuthService
}
