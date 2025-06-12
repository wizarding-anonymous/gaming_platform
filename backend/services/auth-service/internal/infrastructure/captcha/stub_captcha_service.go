// File: backend/services/auth-service/internal/infrastructure/captcha/stub_captcha_service.go
package captcha

import (
	"context"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
	"go.uber.org/zap"
)

type StubCaptchaService struct {
	logger  *zap.Logger
	enabled bool // To simulate enabled/disabled state from config
}

// NewStubCaptchaService creates a new stub implementation of CaptchaService.
func NewStubCaptchaService(cfg config.CaptchaConfig, logger *zap.Logger) service.CaptchaService {
	return &StubCaptchaService{
		logger:  logger.Named("stub_captcha_service"),
		enabled: cfg.Enabled, // Use the 'Enabled' field from CaptchaConfig
	}
}

// Verify always returns true for the stub if enabled and token is not empty, logs a message.
func (s *StubCaptchaService) Verify(ctx context.Context, captchaToken string, ipAddress string) (bool, error) {
	if !s.enabled {
		s.logger.Info("Captcha check skipped as it is disabled in config.")
		return true, nil // If CAPTCHA is disabled, effectively it's always valid
	}
	if captchaToken == "" {
		s.logger.Warn("Captcha verification called with empty token (stub).")
		// In a real scenario, an empty token might be an immediate fail.
		// For a stub, we can decide behavior. Let's say it's a fail for empty token if enabled.
		return false, nil // Or an error like: fmt.Errorf("captcha token is empty")
	}
	s.logger.Info("StubCaptchaService.Verify called",
		zap.String("captchaToken", captchaToken),
		zap.String("ipAddress", ipAddress),
		zap.Bool("is_stub_always_passing_if_token_present", true),
	)
	// Simulate successful verification if enabled and token is present
	return true, nil
}

var _ service.CaptchaService = (*StubCaptchaService)(nil)
