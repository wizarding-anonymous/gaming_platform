// File: internal/domain/service/captcha_service.go
package service

import "context"

// CaptchaService defines the interface for CAPTCHA verification.
type CaptchaService interface {
	// Verify checks the validity of a CAPTCHA token.
	// ipAddress is optional and can be used by some CAPTCHA providers.
	Verify(ctx context.Context, captchaToken string, ipAddress string) (bool, error)
}
