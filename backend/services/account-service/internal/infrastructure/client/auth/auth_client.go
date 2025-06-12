// File: backend/services/account-service/internal/infrastructure/client/auth/auth_client.go
// account-service/internal/infrastructure/client/auth/auth_client.go
package auth

import (
"context"
"fmt"
"time"

"github.com/google/uuid"
"google.golang.org/grpc"
"google.golang.org/grpc/credentials/insecure"

"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/app/usecase"
pb "github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/api/proto/auth"
)

// AuthServiceClientImpl реализация клиента для Auth Service
type AuthServiceClientImpl struct {
client pb.AuthServiceClient
conn   *grpc.ClientConn
}

// NewAuthServiceClient создает новый экземпляр клиента Auth Service
func NewAuthServiceClient(address string) (*AuthServiceClientImpl, error) {
conn, err := grpc.Dial(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
if err != nil {
return nil, fmt.Errorf("failed to connect to auth service: %w", err)
}

client := pb.NewAuthServiceClient(conn)
return &AuthServiceClientImpl{
client: client,
conn:   conn,
}, nil
}

// Close закрывает соединение с Auth Service
func (c *AuthServiceClientImpl) Close() error {
if c.conn != nil {
return c.conn.Close()
}
return nil
}

// ValidateToken проверяет валидность JWT токена
func (c *AuthServiceClientImpl) ValidateToken(ctx context.Context, token string) (*usecase.TokenClaims, error) {
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()

resp, err := c.client.ValidateToken(ctx, &pb.ValidateTokenRequest{
Token: token,
})
if err != nil {
return nil, fmt.Errorf("failed to validate token: %w", err)
}

if !resp.Valid {
return nil, fmt.Errorf("invalid token")
}

accountID, err := uuid.Parse(resp.AccountId)
if err != nil {
return nil, fmt.Errorf("invalid account ID in token: %w", err)
}

return &usecase.TokenClaims{
AccountID: accountID,
Username:  resp.Username,
Email:     resp.Email,
Role:      resp.Role,
ExpiresAt: time.Unix(resp.ExpiresAt, 0),
}, nil
}

// GenerateToken генерирует новый JWT токен
func (c *AuthServiceClientImpl) GenerateToken(ctx context.Context, accountID uuid.UUID, username, email, role string) (string, error) {
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()

resp, err := c.client.GenerateToken(ctx, &pb.GenerateTokenRequest{
AccountId: accountID.String(),
Username:  username,
Email:     email,
Role:      role,
})
if err != nil {
return "", fmt.Errorf("failed to generate token: %w", err)
}

return resp.Token, nil
}

// RevokeToken отзывает JWT токен
func (c *AuthServiceClientImpl) RevokeToken(ctx context.Context, token string) error {
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()

_, err := c.client.RevokeToken(ctx, &pb.RevokeTokenRequest{
Token: token,
})
if err != nil {
return fmt.Errorf("failed to revoke token: %w", err)
}

return nil
}

// VerifyPermission проверяет наличие разрешения у пользователя
func (c *AuthServiceClientImpl) VerifyPermission(ctx context.Context, accountID uuid.UUID, permission string) (bool, error) {
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()

resp, err := c.client.VerifyPermission(ctx, &pb.VerifyPermissionRequest{
AccountId:  accountID.String(),
Permission: permission,
})
if err != nil {
return false, fmt.Errorf("failed to verify permission: %w", err)
}

return resp.HasPermission, nil
}

// GetRolePermissions получает список разрешений для роли
func (c *AuthServiceClientImpl) GetRolePermissions(ctx context.Context, role string) ([]string, error) {
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()

resp, err := c.client.GetRolePermissions(ctx, &pb.GetRolePermissionsRequest{
Role: role,
})
if err != nil {
return nil, fmt.Errorf("failed to get role permissions: %w", err)
}

return resp.Permissions, nil
}
