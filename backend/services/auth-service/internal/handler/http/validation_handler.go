// File: backend/services/auth-service/internal/handler/http/validation_handler.go
package http

import (
	"net/http"
	// "strings"
	"encoding/json" // For IntrospectionResponse if it's complex

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models" // For DTOs (already here)
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	domainService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/service" // For concrete AuthService
)

// ValidationHandler handles requests for token validation and permission checks.
type ValidationHandler struct {
	logger                 *zap.Logger
	tokenManagementService domainService.TokenManagementService
	authService            *service.AuthService // For CheckPermission logic
}

// NewValidationHandler creates a new ValidationHandler.
// The old NewValidationHandler in router.go took (tokenService, tokenManagementService, logger).
// This needs to be consistent. Assuming authService is needed for CheckPermission.
func NewValidationHandler(
	logger *zap.Logger,
	tokenManagementService domainService.TokenManagementService,
	authService *service.AuthService, // Keep authService for CheckPermission
) *ValidationHandler {
	return &ValidationHandler{
		logger:                 logger.Named("validation_handler"),
		tokenManagementService: tokenManagementService,
		authService:            authService,
	}
}

// ValidateToken handles requests to validate an access token.
// POST /api/v1/validation/token
func (h *ValidationHandler) ValidateToken(c *gin.Context) {
	var req models.ValidateTokenRequest // Use DTO from models package
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	claims, err := h.tokenManagementService.ValidateAccessToken(req.Token)
	if err != nil {
		h.logger.Debug("ValidateToken: Token validation failed", zap.Error(err), zap.String("token_prefix",SafeTokenPrefix(req.Token)))

		resp := models.ValidateTokenResponse{Valid: false, Error: &models.ErrorResponseMessage{Message: "Invalid or expired token"}}
		if errors.Is(err, domainErrors.ErrExpiredToken) {
			resp.Error.Code = "token_expired"
		} else {
			resp.Error.Code = "token_invalid"
		}
		c.JSON(http.StatusOK, resp)
		return
	}

	SuccessResponse(c.Writer, h.logger, http.StatusOK, models.ValidateTokenResponse{ // Use DTO from models
		Valid:       true,
		UserID:      claims.UserID,
		Roles:       claims.Roles,
		Permissions: claims.Permissions,
		SessionID:   claims.SessionID,
		ExpiresAt:   claims.ExpiresAt.Unix(),
		IssuedAt:    claims.IssuedAt.Unix(),
		Issuer:      claims.Issuer,
		Audience:    claims.Audience,
	})
}

// CheckPermission handles requests to check if a user has a specific permission.
// POST /api/v1/validation/permission
func (h *ValidationHandler) CheckPermission(c *gin.Context) {
	var req models.CheckPermissionRequest // Use DTO from models package
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid user_id format", err)
		return
	}

	// This requires AuthService to have a method like:
	// CheckUserPermission(ctx context.Context, userID uuid.UUID, permissionKey string, resourceID *string) (bool, error)
	hasPermission, err := h.authService.CheckUserPermission(c.Request.Context(), userID, req.Permission, req.ResourceID)
	if err != nil {
		h.logger.Error("CheckPermission: Error checking permission in service", zap.Error(err),
			zap.String("userID", req.UserID), zap.String("permission", req.Permission))
		ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to check permission", err)
		return
	}

	SuccessResponse(c.Writer, h.logger, http.StatusOK, models.CheckPermissionResponse{HasPermission: hasPermission}) // Use DTO from models
}

// IntrospectToken handles token introspection requests (RFC 7662 style).
// POST /api/v1/validation/introspect
func (h *ValidationHandler) IntrospectToken(c *gin.Context) {
	var req models.IntrospectTokenRequest // Use DTO from models package
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	claims, err := h.tokenManagementService.ValidateAccessToken(req.Token)
	if err != nil {
		h.logger.Debug("IntrospectToken: Token validation failed", zap.Error(err), zap.String("token_prefix", SafeTokenPrefix(req.Token)))
		c.JSON(http.StatusOK, models.IntrospectionResponse{Active: false}) // Use DTO from models
		return
	}

	resp := models.IntrospectionResponse{ // Use DTO from models
		Active:      true,
		Subject:     claims.Subject,
		UserID:      claims.UserID,
		Username:    claims.Username,
		Audience:    claims.Audience,
		Issuer:      claims.Issuer,
		JWTID:       claims.ID,
		ExpiresAt:   claims.ExpiresAt.Unix(),
		IssuedAt:    claims.IssuedAt.Unix(),
		NotBefore:   claims.NotBefore.Unix(),
		Roles:       claims.Roles,
		Permissions: claims.Permissions,
		SessionID:   claims.SessionID,
		TokenType:   "Bearer",
	}
	SuccessResponse(c.Writer, h.logger, http.StatusOK, resp)
}

// SafeTokenPrefix returns a short prefix of a token for logging.
func SafeTokenPrefix(token string) string {
	if len(token) > 8 {
		return token[:8] + "..."
	}
	return token
}

// Assuming ErrorResponse and SuccessResponse are defined elsewhere (e.g. base_handler.go or similar)
// For this file to be self-contained for now:
/*
func SuccessResponse(w http.ResponseWriter, logger *zap.Logger, statusCode int, data interface{}) {
	// ... implementation ...
}
func ErrorResponse(w http.ResponseWriter, logger *zap.Logger, statusCode int, message string, details error) {
	// ... implementation ...
}
*/
