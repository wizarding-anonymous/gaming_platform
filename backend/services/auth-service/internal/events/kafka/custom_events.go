// File: backend/services/auth-service/internal/events/kafka/custom_events.go
package kafka

import (
	"context"
	"time"
)

// AccountLinkedEvent represents a user linking an external account.
type AccountLinkedEvent struct {
	UserID         string    `json:"user_id"`
	Provider       string    `json:"provider"`
	ProviderUserID string    `json:"provider_user_id"`
	Timestamp      time.Time `json:"timestamp"`
}

// UserRegisteredEvent represents a new user registration via OAuth or Telegram.
type UserRegisteredEvent struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	AuthType  string    `json:"auth_type"`
	Timestamp time.Time `json:"timestamp"`
}

// UserLoggedInEvent represents a user login via external provider.
type UserLoggedInEvent struct {
	UserID     string    `json:"user_id"`
	SessionID  string    `json:"session_id"`
	LoginTime  time.Time `json:"login_time"`
	UserAgent  string    `json:"user_agent"`
	IPAddress  string    `json:"ip_address"`
	AuthMethod string    `json:"auth_method"`
}

// The following methods are placeholders to satisfy usages in service tests.
func (p *Producer) PublishAccountLinkedEvent(ctx context.Context, event AccountLinkedEvent) error {
	return nil
}

func (p *Producer) PublishUserRegisteredEvent(ctx context.Context, event UserRegisteredEvent) error {
	return nil
}

func (p *Producer) PublishUserLoggedInEvent(ctx context.Context, event UserLoggedInEvent) error {
	return nil
}
