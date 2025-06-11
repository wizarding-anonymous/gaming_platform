// File: backend/services/auth-service/internal/handler/grpc/interceptors/auth.go

package interceptors

import (
	"context"
	"strings"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/service"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// AuthInterceptor представляет перехватчик для аутентификации gRPC-запросов
type AuthInterceptor struct {
	tokenService *service.TokenService
	logger       *zap.Logger
	// Карта методов, которые не требуют аутентификации
	publicMethods map[string]bool
}

// NewAuthInterceptor создает новый экземпляр AuthInterceptor
func NewAuthInterceptor(tokenService *service.TokenService, logger *zap.Logger) *AuthInterceptor {
	// Инициализация карты публичных методов
	publicMethods := map[string]bool{
		"/auth.AuthService/Login":         true,
		"/auth.AuthService/RefreshToken":  true,
		"/auth.AuthService/Register":      true,
		"/auth.AuthService/ValidateToken": true,
	}

	return &AuthInterceptor{
		tokenService:  tokenService,
		logger:        logger,
		publicMethods: publicMethods,
	}
}

// Unary возвращает унарный перехватчик для аутентификации
func (i *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Проверка, является ли метод публичным
		if i.publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Аутентификация
		userID, err := i.authenticate(ctx)
		if err != nil {
			return nil, err
		}

		// Добавление ID пользователя в контекст
		ctx = context.WithValue(ctx, "user_id", userID)

		// Вызов обработчика
		return handler(ctx, req)
	}
}

// Stream возвращает потоковый перехватчик для аутентификации
func (i *AuthInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Проверка, является ли метод публичным
		if i.publicMethods[info.FullMethod] {
			return handler(srv, ss)
		}

		// Аутентификация
		userID, err := i.authenticate(ss.Context())
		if err != nil {
			return err
		}

		// Создание обертки для потока с контекстом, содержащим ID пользователя
		wrappedStream := &wrappedServerStream{
			ServerStream: ss,
			ctx:          context.WithValue(ss.Context(), "user_id", userID),
		}

		// Вызов обработчика
		return handler(srv, wrappedStream)
	}
}

// authenticate проверяет токен в метаданных запроса
func (i *AuthInterceptor) authenticate(ctx context.Context) (string, error) {
	// Получение метаданных из контекста
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "metadata is not provided")
	}

	// Получение токена из метаданных
	values := md.Get("authorization")
	if len(values) == 0 {
		return "", status.Error(codes.Unauthenticated, "authorization token is not provided")
	}

	// Проверка формата токена
	authHeader := values[0]
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", status.Error(codes.Unauthenticated, "invalid authorization format, expected 'Bearer {token}'")
	}

	// Извлечение токена
	token := authHeader[7:]

	// Валидация токена
	_, claims, err := i.tokenService.ValidateAccessToken(ctx, token)
	if err != nil {
		i.logger.Error("Token validation failed", zap.Error(err))
		return "", status.Error(codes.Unauthenticated, "invalid token")
	}

	// Получение ID пользователя из claims
	userID, ok := claims["sub"].(string)
	if !ok {
		return "", status.Error(codes.Internal, "invalid token claims")
	}

	return userID, nil
}

// wrappedServerStream представляет обертку для gRPC-потока с пользовательским контекстом
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context возвращает пользовательский контекст
func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}
