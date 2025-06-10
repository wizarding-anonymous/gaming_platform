// File: backend/services/auth-service/internal/domain/interfaces/notification_service.go
package interfaces

import (
	"context"
	"github.com/google/uuid"
)

// NotificationService defines the interface for sending notifications to users.
type NotificationService interface {
	// SendEmailVerificationNotification sends an email verification code to the user.
	SendEmailVerificationNotification(ctx context.Context, userID uuid.UUID, code string) error
}
