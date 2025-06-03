// File: internal/handler/http/router.go

package http

import (
	"github.com/gin-gonic/gin"
	"github.com/your-org/auth-service/internal/handler/http/middleware"
	"github.com/your-org/auth-service/internal/service"
	"github.com/your-org/auth-service/internal/utils/telemetry"
	"go.uber.org/zap"
)

// SetupRouter настраивает маршрутизацию HTTP
func SetupRouter(
	authService *service.AuthService,
	userService *service.UserService,
	roleService *service.RoleService,
	tokenService *service.TokenService,
	twoFactorService *service.TwoFactorService,
	telegramService *service.TelegramService,
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
	authHandler := NewAuthHandler(authService, tokenService, twoFactorService, telegramService, logger)
	userHandler := NewUserHandler(userService, logger)
	roleHandler := NewRoleHandler(roleService, logger)
	validationHandler := NewValidationHandler(tokenService, logger)

	// Настройка маршрутов для метрик и проверки работоспособности
	router.GET("/metrics", gin.WrapF(telemetry.PrometheusHandler()))
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	router.GET("/readiness", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Группа маршрутов API
	api := router.Group("/api/v1")
	{
		// Маршруты аутентификации (публичные)
		auth := api.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/telegram-login", authHandler.TelegramLogin)
			auth.POST("/refresh-token", authHandler.RefreshToken)
			auth.POST("/verify-email", authHandler.VerifyEmail)
			auth.POST("/resend-verification", authHandler.ResendVerification)
			auth.POST("/forgot-password", authHandler.ForgotPassword)
			auth.POST("/reset-password", authHandler.ResetPassword)
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
		protected.Use(middleware.AuthMiddleware(tokenService, logger))
		{
			// Маршруты пользователя
			user := protected.Group("/users")
			{
				user.GET("/me", userHandler.GetCurrentUser)
				user.PUT("/me", userHandler.UpdateUser)
				user.POST("/change-password", userHandler.ChangePassword)
				user.DELETE("/me", userHandler.DeleteUser)
				user.GET("/:id", userHandler.GetUser)
			}

			// Маршруты 2FA
			twoFactor := protected.Group("/2fa")
			{
				twoFactor.POST("/enable", authHandler.Enable2FA)
				twoFactor.POST("/verify", authHandler.Verify2FA)
				twoFactor.POST("/disable", authHandler.Disable2FA)
			}

			// Маршруты выхода
			logout := protected.Group("/auth")
			{
				logout.POST("/logout", authHandler.Logout)
				logout.POST("/logout-all", authHandler.LogoutAll)
			}
		}

		// Маршруты администратора (требуют роли admin)
		admin := api.Group("/admin")
		admin.Use(middleware.AuthMiddleware(tokenService, logger))
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
				roles.POST("/assign", roleHandler.AssignRoleToUser)
				roles.POST("/remove", roleHandler.RemoveRoleFromUser)
				roles.GET("/user/:id", roleHandler.GetUserRoles)
			}
		}
	}

	return router
}
