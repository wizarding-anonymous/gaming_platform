// File: internal/handler/http/router.go

package http

import (
	"github.com/gin-gonic/gin"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/handler/http/middleware"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/service"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/telemetry"
	"go.uber.org/zap"
)

// SetupRouter настраивает маршрутизацию HTTP
func SetupRouter(
	authService *service.AuthService,
	userService *service.UserService,
	roleService *service.RoleService,
	tokenService *service.TokenService, // Old token service, may still be used by some handlers if not fully refactored
	sessionService *service.SessionService,
	// twoFactorService *service.TwoFactorService, // Replaced by mfaLogicService for core 2FA logic
	telegramService *service.TelegramService, // Assuming this is still separate
	mfaLogicService domainService.MFALogicService,
	apiKeyService domainService.APIKeyService,
	auditLogService domainService.AuditLogService, // Added for AdminHandler
	tokenManagementService domainService.TokenManagementService,
	cfg *config.Config,
	logger *zap.Logger,
) *gin.Engine {
	// Создание роутера
	router := gin.New()

	// Применение middleware
	router.Use(middleware.RecoveryMiddleware(logger))
	router.Use(middleware.LoggingMiddleware(logger))
	router.Use(middleware.CorsMiddleware())
	router.Use(middleware.MetricsMiddleware())
	router.Use(middleware.TracingMiddleware())

	// Создание обработчиков
	authHandler := NewAuthHandler(logger, authService, mfaLogicService, tokenManagementService, cfg)
	userHandler := NewUserHandler(userService, authService, sessionService, mfaLogicService, apiKeyService, logger)
	roleHandler := NewRoleHandler(roleService, logger) // Assuming RoleService DI is stable
	adminHandler := NewAdminHandler(logger, userService, roleService, auditLogService) // Instantiate AdminHandler
	validationHandler := NewValidationHandler(logger, tokenManagementService, authService) // Updated NewValidationHandler call
	meHandler := NewMeHandler(logger, authService, userService, mfaLogicSvc, apiKeyService, sessionService) // Instantiate MeHandler, added sessionService
	oauthHandler := NewOAuthHandler(authService, logger, cfg) // Инициализация OAuthHandler


	// Настройка маршрутов для метрик и проверки работоспособности
	router.GET("/metrics", gin.WrapF(telemetry.PrometheusHandler()))
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	router.GET("/readiness", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// JWKS Endpoint
	jwksHandler := NewJWKSHandler(tokenManagementService, logger)
	// Standard path for JWKS. Can also be /api/v1/auth/jwks.json if preferred under API group.
	router.GET("/.well-known/jwks.json", gin.WrapF(jwksHandler.GetJWKS))


	// Группа маршрутов API
	api := router.Group("/api/v1")
	{
		// Маршруты аутентификации (публичные)
		auth := api.Group("/auth")
		{
			auth.POST("/register", authHandler.RegisterUser) // Corrected name
			auth.POST("/login", authHandler.LoginUser)       // Corrected name
			auth.POST("/telegram-login", authHandler.TelegramLogin)
			auth.POST("/refresh-token", authHandler.RefreshToken)
			auth.POST("/verify-email", authHandler.VerifyEmail)
			auth.POST("/resend-verification", authHandler.ResendVerification)
			auth.POST("/forgot-password", authHandler.ForgotPassword)
			auth.POST("/reset-password", authHandler.ResetPassword)
			auth.POST("/login/2fa/verify", authHandler.VerifyLogin2FA)

			// OAuth and other external provider routes
			auth.GET("/oauth/:provider", oauthHandler.InitiateOAuthHandler)     // Redirect to provider
			auth.GET("/oauth/:provider/callback", oauthHandler.OAuthCallbackHandler) // Callback from provider
			// TelegramLogin route auth.POST("/telegram-login", authHandler.TelegramLogin) is already present
		}

		// Маршруты валидации (для внутреннего использования)
		validation := api.Group("/validation")
		{
			validation.POST("/token", validationHandler.ValidateToken)
			validation.POST("/permission", validationHandler.CheckPermission)
			validation.POST("/introspect", validationHandler.IntrospectToken)
		}

		// Защищенные маршруты (требуют аутентификации)
		protected := api.Group("/")
		// AuthMiddleware might need TokenManagementService if access tokens are RS256
		protected.Use(middleware.AuthMiddleware(tokenManagementService, logger))
		{
			// Register /me routes using MeHandler
			RegisterMeRoutes(protected, meHandler)

			// Admin/general user routes (if any user can access /users/:id or if it's admin only)
			// For now, assuming /users/:id is more general or admin, distinct from /me
			userRoutes := protected.Group("/users")
			{
				userRoutes.GET("/:id", userHandler.GetUser) // GET /api/v1/users/:id
				// Add other /users routes here if they are general and not /me specific
			}

			// Маршруты 2FA (Old group removed)
			// twoFactor := protected.Group("/2fa")
			// {
			// 	twoFactor.POST("/enable", authHandler.Enable2FA)
			// 	twoFactor.POST("/verify", authHandler.Verify2FA)
			// 	twoFactor.POST("/disable", authHandler.Disable2FA)
			// }

			// Маршруты выхода
			logout := protected.Group("/auth")
			{
				logout.POST("/logout", authHandler.Logout)
				logout.POST("/logout-all", authHandler.LogoutAll)
			}
		}

		// Маршруты администратора (требуют роли admin)
		admin := api.Group("/admin")
		// AuthMiddleware for admin routes
		admin.Use(middleware.AuthMiddleware(tokenManagementService, logger))
		admin.Use(middleware.RoleMiddleware([]string{"admin"}))
		{
			// Маршруты управления ролями
			roles := admin.Group("/roles")
			{
				roles.GET("", roleHandler.GetRoles)
				roles.POST("", roleHandler.CreateRole)
				roles.GET("/:id", roleHandler.GetRole)
				roles.PUT("/:id", roleHandler.UpdateRole)
				roles.DELETE("/:id", roleHandler.DeleteRole)
			// These might be part of RoleService or a more specific UserRoleService if complex
			// For now, assuming roleHandler has these or similar if they are simple role property changes
			// roles.POST("/assign", roleHandler.AssignRoleToUser) // This was likely for admin to assign role to any user
			// roles.POST("/remove", roleHandler.RemoveRoleFromUser) // This too
			// roles.GET("/user/:id", roleHandler.GetUserRoles) // This too
			// The UpdateUserRoles in AdminHandler is now PUT /admin/users/{user_id}/roles
			}

			// Admin User Management (already handled by adminHandler instance)
			adminUsers := admin.Group("/users")
			{
				adminUsers.GET("", adminHandler.ListUsers)
				adminUsers.GET("/:user_id", adminHandler.GetUserByID)
				adminUsers.POST("/:user_id/block", adminHandler.BlockUser)
				adminUsers.POST("/:user_id/unblock", adminHandler.UnblockUser)
				adminUsers.PUT("/:user_id/roles", adminHandler.UpdateUserRoles)
			}

			// Admin Audit Logs
			adminAudit := admin.Group("/audit-logs")
			{
				adminAudit.GET("", adminHandler.ListAuditLogs)
			}
		}
	}

	return router
}
