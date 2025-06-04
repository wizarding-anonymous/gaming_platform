package http

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/gameplatform/auth-service/internal/domain/entity"
	"github.com/gameplatform/auth-service/internal/domain/service"
	// "github.com/gameplatform/auth-service/internal/middleware" // For auth middleware constants
)

// MeHandler handles HTTP requests for the current authenticated user (`/me/...`).
type MeHandler struct {
	logger         *zap.Logger
	authLogicSvc   service.AuthLogicService 
	userService    service.UserService      
	mfaLogicSvc    service.MFALogicService  
	apiKeySvc      service.APIKeyService    
	sessionSvc     service.SessionService   
}

// NewMeHandler creates a new MeHandler.
func NewMeHandler(
	logger *zap.Logger,
	authLogicSvc service.AuthLogicService,
	userService service.UserService,
	mfaLogicSvc service.MFALogicService,
	apiKeySvc service.APIKeyService,
	sessionSvc service.SessionService, 
) *MeHandler {
	return &MeHandler{
		logger:       logger.Named("me_handler"),
		authLogicSvc: authLogicSvc,
		userService:  userService,
		mfaLogicSvc:  mfaLogicSvc,
		apiKeySvc:    apiKeySvc,
		sessionSvc:   sessionSvc,
	}
}

// --- DTOs ---
// Assuming UserResponse, ChangePasswordRequest, CreateAPIKeyRequest, APIKeyDetailsDTO, 
// CreateAPIKeyResponse, ListAPIKeysResponse, Meta are defined (e.g. in auth_handler.go or a shared DTO spot)

type EnableTOTPResponse struct {
	SecretKey     string `json:"secret_key"`     
	QRCodeDataURL string `json:"qr_code_image"` 
}

type VerifyTOTPActivateRequest struct {
	TOTPCode string `json:"totp_code" binding:"required,len=6"`
}

type VerifyTOTPActivateResponse struct {
	Message     string   `json:"message"` 
	BackupCodes []string `json:"backup_codes"`
}

type Disable2FARequest struct {
	Password string `json:"password,omitempty"` 
	TOTPCode string `json:"totp_code,omitempty"` 
}

type RegenerateBackupCodesRequest struct { // Can be same as Disable2FARequest if verification is similar
    Password string `json:"password,omitempty"`
    TOTPCode string `json:"totp_code,omitempty"`
}

type RegenerateBackupCodesResponse struct {
	BackupCodes []string `json:"backup_codes"`
}

type SessionInfoDTO struct {
	ID             string          `json:"id"`
	IPAddress      *string         `json:"ip_address,omitempty"`
	UserAgent      *string         `json:"user_agent,omitempty"`
	DeviceInfo     json.RawMessage `json:"device_info,omitempty"` // Assuming DeviceInfo in entity.Session is json.RawMessage
	LastActivityAt *time.Time      `json:"last_activity_at,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	IsCurrent      bool            `json:"is_current"`
}
type ListSessionsResponse struct {
	Data []SessionInfoDTO `json:"data"`
	Meta Meta             `json:"meta"`
}


// --- Helper ---
func (h *MeHandler) respondWithError(c *gin.Context, code int, message string) {
	c.AbortWithStatusJSON(code, gin.H{"error": message})
}

func (h *MeHandler) getUserIDFromContext(c *gin.Context) (string, bool) {
	userIDVal, exists := c.Get("userID") 
	if !exists {
		userIDStr := c.GetString("userID") 
		if userIDStr == "" {
			h.logger.Error("userID not found in context, auth middleware missing or not run")
			h.respondWithError(c, http.StatusUnauthorized, "Unauthorized: Missing user identification")
			return "", false
		}
		return userIDStr, true
	}
	userIDStr, ok := userIDVal.(string)
	if !ok || userIDStr == "" {
		h.logger.Error("userID in context is not a valid string", zap.Any("userID", userIDVal))
		h.respondWithError(c, http.StatusUnauthorized, "Unauthorized: Invalid user identification")
		return "", false
	}
	return userIDStr, true
}

func (h *MeHandler) getCurrentSessionIDFromContext(c *gin.Context) string {
	sessionIDVal, _ := c.Get("sessionID") // or "jti" from token claims
	sessionID, _ := sessionIDVal.(string)
	return sessionID
}


// --- Handlers ---

func (h *MeHandler) GetMe(c *gin.Context) {
	userID, ok := h.getUserIDFromContext(c)
	if !ok { return }

	user, mfaEnabled, err := h.userService.GetUserFullInfo(c.Request.Context(), userID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(c, http.StatusNotFound, "User not found")
		} else {
			h.logger.Error("GetMe: failed to get user full info", zap.Error(err), zap.String("userID", userID))
			h.respondWithError(c, http.StatusInternalServerError, "Failed to retrieve user information")
		}
		return
	}
	
	// Re-using UserResponse from auth_handler.go, ensure it has MFAEnabled or use a specific MeDTO
	responseMap := map[string]interface{}{
        "id":          user.ID, "username":    user.Username, "email":       user.Email,
        "status":      string(user.Status), "created_at":  user.CreatedAt,
		"email_verified_at": user.EmailVerifiedAt, "last_login_at": user.LastLoginAt,
        "mfa_enabled": mfaEnabled,
    }
	c.JSON(http.StatusOK, responseMap)
}

func (h *MeHandler) ChangePasswordHandler(c *gin.Context) {
	userID, ok := h.getUserIDFromContext(c)
	if !ok { return }

	var req ChangePasswordRequest 
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}

	err := h.authLogicSvc.ChangePasswordForUser(c.Request.Context(), userID, req.CurrentPassword, req.NewPassword)
	if err != nil {
		if strings.Contains(err.Error(), "incorrect") { 
			h.respondWithError(c, http.StatusUnauthorized, err.Error())
		} else if strings.Contains(err.Error(), "weak") || strings.Contains(err.Error(), "validation") { 
			h.respondWithError(c, http.StatusBadRequest, err.Error())
		} else {
			h.logger.Error("ChangePasswordHandler: service error", zap.Error(err), zap.String("userID", userID))
			h.respondWithError(c, http.StatusInternalServerError, "Failed to change password")
		}
		return
	}
	c.Status(http.StatusNoContent)
}

// --- /me/sessions ---
func (h *MeHandler) ListMySessionsHandler(c *gin.Context) {
	userID, ok := h.getUserIDFromContext(c)
	if !ok { return }
	
	currentSessionID := h.getCurrentSessionIDFromContext(c) 

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "10"))

	sessions, total, err := h.sessionSvc.ListUserSessions(c.Request.Context(), userID, page, perPage, currentSessionID)
	if err != nil {
		h.logger.Error("ListMySessionsHandler: service error", zap.Error(err), zap.String("userID", userID))
		h.respondWithError(c, http.StatusInternalServerError, "Failed to retrieve sessions.")
		return
	}

	sessionDTOs := make([]SessionInfoDTO, len(sessions))
	for i, s := range sessions {
		sessionDTOs[i] = SessionInfoDTO{
			ID:             s.ID,
			IPAddress:      s.IPAddress,
			UserAgent:      s.UserAgent,
			DeviceInfo:     s.DeviceInfo, // Assuming entity.Session.DeviceInfo is json.RawMessage
			LastActivityAt: s.LastActivityAt,
			CreatedAt:      s.CreatedAt,
			IsCurrent:      s.IsCurrent, 
		}
	}
	
	totalPages := 0
	if perPage > 0 && total > 0 { totalPages = (total + perPage -1) / perPage }

	c.JSON(http.StatusOK, ListSessionsResponse{
		Data: sessionDTOs,
		Meta: Meta{CurrentPage: page, PerPage: perPage, TotalItems: total, TotalPages: totalPages},
	})
}

func (h *MeHandler) RevokeMySessionHandler(c *gin.Context) {
	userID, ok := h.getUserIDFromContext(c)
	if !ok { return }

	sessionIDToRevoke := c.Param("session_id")
	if sessionIDToRevoke == "" { 
		h.respondWithError(c, http.StatusBadRequest, "Session ID is required in path.")
		return
	}
	
	err := h.sessionSvc.RevokeUserSession(c.Request.Context(), userID, sessionIDToRevoke, h.getCurrentSessionIDFromContext(c))
	if err != nil {
		h.logger.Error("RevokeMySessionHandler: service error", zap.Error(err), zap.String("userID", userID), zap.String("session_id_to_revoke", sessionIDToRevoke))
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(c, http.StatusNotFound, "Session not found or not owned by user.")
		} else if strings.Contains(err.Error(), "cannot revoke current session") {
			h.respondWithError(c, http.StatusBadRequest, "Cannot revoke current session with this endpoint. Use /logout.")
		} else {
			h.respondWithError(c, http.StatusInternalServerError, "Failed to revoke session.")
		}
		return
	}
	c.Status(http.StatusNoContent)
}


// --- /me/2fa ---
func (h *MeHandler) Enable2FAInitiateHandler(c *gin.Context) {
	userID, ok := h.getUserIDFromContext(c)
	if !ok { return }

	userEntity, _, errUser := h.userService.GetUserFullInfo(c.Request.Context(), userID)
	if errUser != nil {
		h.logger.Error("Enable2FAInitiateHandler: failed to get user for issuer name", zap.Error(errUser), zap.String("userID", userID))
		h.respondWithError(c, http.StatusInternalServerError, "Failed to initiate 2FA setup.")
		return
	}
	
	secret, qrCodeDataURL, err := h.mfaLogicSvc.Enable2FAInitiate(c.Request.Context(), userID, userEntity.Email, "YourPlatformName")
	if err != nil {
		h.logger.Error("Enable2FAInitiateHandler: service error", zap.Error(err), zap.String("userID", userID))
		if strings.Contains(err.Error(), "already verified and active") || strings.Contains(err.Error(), "already pending") {
			h.respondWithError(c, http.StatusConflict, err.Error())
		} else {
			h.respondWithError(c, http.StatusInternalServerError, "Failed to initiate 2FA setup.")
		}
		return
	}
	c.JSON(http.StatusOK, EnableTOTPResponse{SecretKey: secret, QRCodeDataURL: qrCodeDataURL})
}

func (h *MeHandler) VerifyAndActivate2FAHandler(c *gin.Context) {
	userID, ok := h.getUserIDFromContext(c)
	if !ok { return }

	var req VerifyTOTPActivateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}

	backupCodes, err := h.mfaLogicSvc.VerifyAndActivate2FA(c.Request.Context(), userID, req.TOTPCode)
	if err != nil {
		h.logger.Error("VerifyAndActivate2FAHandler: service error", zap.Error(err), zap.String("userID", userID))
		if strings.Contains(err.Error(), "invalid TOTP code") {
			h.respondWithError(c, http.StatusBadRequest, err.Error())
		} else if strings.Contains(err.Error(), "already verified") || strings.Contains(err.Error(), "not initiated") {
			h.respondWithError(c, http.StatusConflict, err.Error())
		} else {
			h.respondWithError(c, http.StatusInternalServerError, "Failed to verify and activate 2FA.")
		}
		return
	}
	c.JSON(http.StatusOK, VerifyTOTPActivateResponse{
		Message:     "Two-Factor Authentication enabled successfully. Please save your backup codes securely.",
		BackupCodes: backupCodes,
	})
}

func (h *MeHandler) Disable2FAHandler(c *gin.Context) {
	userID, ok := h.getUserIDFromContext(c)
	if !ok { return }

	var req Disable2FARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}

	var verificationToken string
	var verificationType string
	if req.Password != "" {
		verificationToken = req.Password
		verificationType = "password"
	} else if req.TOTPCode != "" {
		verificationToken = req.TOTPCode
		verificationType = "totp"
	} else {
		h.respondWithError(c, http.StatusBadRequest, "Password or TOTP code required to disable 2FA.")
		return
	}

	err := h.mfaLogicSvc.Disable2FA(c.Request.Context(), userID, verificationToken, verificationType)
	if err != nil {
		h.logger.Error("Disable2FAHandler: service error", zap.Error(err), zap.String("userID", userID))
		if strings.Contains(err.Error(), "invalid verification") || strings.Contains(err.Error(), "not enabled") {
			h.respondWithError(c, http.StatusForbidden, err.Error())
		} else {
			h.respondWithError(c, http.StatusInternalServerError, "Failed to disable 2FA.")
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Two-Factor Authentication disabled successfully."})
}

func (h *MeHandler) RegenerateBackupCodesHandler(c *gin.Context) {
    userID, ok := h.getUserIDFromContext(c)
    if !ok { return }

    var req RegenerateBackupCodesRequest 
	if err := c.ShouldBindJSON(&req); err != nil {
		// Allow empty body if verification is, for example, only via current valid TOTP session
		// However, explicit verification is better.
		// For this example, we expect password or totp_code in body.
		h.respondWithError(c, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}
	var verificationToken string
	var verificationType string
	if req.Password != "" {
		verificationToken = req.Password
		verificationType = "password"
	} else if req.TOTPCode != "" {
		verificationToken = req.TOTPCode
		verificationType = "totp"
	} else {
		h.respondWithError(c, http.StatusBadRequest, "Password or TOTP code required to regenerate backup codes.")
		return
	}

    backupCodes, err := h.mfaLogicSvc.RegenerateBackupCodes(c.Request.Context(), userID, verificationToken, verificationType)
    if err != nil {
        h.logger.Error("RegenerateBackupCodesHandler: service error", zap.Error(err), zap.String("userID", userID))
        if strings.Contains(err.Error(), "2FA not active") || strings.Contains(err.Error(), "invalid verification") {
            h.respondWithError(c, http.StatusConflict, err.Error())
        } else { 
            h.respondWithError(c, http.StatusInternalServerError, "Failed to regenerate backup codes.")
        }
        return
    }
    c.JSON(http.StatusOK, RegenerateBackupCodesResponse{BackupCodes: backupCodes})
}


// --- /me/api-keys ---
func (h *MeHandler) CreateAPIKeyHandler(c *gin.Context) {
	userID, ok := h.getUserIDFromContext(c)
	if !ok { return }

	var req CreateAPIKeyRequest 
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}

	rawAPIKey, storedKey, err := h.apiKeySvc.GenerateAndStoreAPIKey(c.Request.Context(), userID, req.Name, req.Permissions, req.ExpiresAt)
	if err != nil {
		h.logger.Error("CreateAPIKeyHandler: service error", zap.Error(err), zap.String("userID", userID))
		h.respondWithError(c, http.StatusInternalServerError, "Failed to create API key")
		return
	}

	c.JSON(http.StatusCreated, CreateAPIKeyResponse{ 
		RawAPIKey: rawAPIKey,
		KeyDetails: APIKeyDetailsDTO{
			ID:          storedKey.ID, Name:        storedKey.Name, KeyPrefix:   storedKey.KeyPrefix,
			Permissions: storedKey.Permissions, CreatedAt:   storedKey.CreatedAt, ExpiresAt:   storedKey.ExpiresAt,
		},
	})
}

func (h *MeHandler) ListAPIKeysHandler(c *gin.Context) {
	userID, ok := h.getUserIDFromContext(c)
	if !ok { return }

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "10"))
	
	keys, total, err := h.apiKeySvc.ListUserAPIKeys(c.Request.Context(), userID, page, perPage)
	if err != nil {
		h.logger.Error("ListAPIKeysHandler: service error", zap.Error(err), zap.String("userID", userID))
		h.respondWithError(c, http.StatusInternalServerError, "Failed to list API keys")
		return
	}

	keyDTOs := make([]APIKeyDetailsDTO, len(keys))
	for i, k := range keys {
		keyDTOs[i] = APIKeyDetailsDTO{
			ID: k.ID, Name: k.Name, KeyPrefix: k.KeyPrefix, Permissions: k.Permissions,
			CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt, ExpiresAt: k.ExpiresAt, RevokedAt: k.RevokedAt,
		}
	}
	
	totalPages := 0
	if perPage > 0 && total > 0 { totalPages = (total + perPage -1) / perPage }

	c.JSON(http.StatusOK, ListAPIKeysResponse{ 
		Data: keyDTOs,
		Meta: Meta{ CurrentPage: page, PerPage: perPage, TotalItems: total, TotalPages: totalPages },
	})
}

func (h *MeHandler) DeleteAPIKeyHandler(c *gin.Context) {
    userID, ok := h.getUserIDFromContext(c)
    if !ok { return }

    keyID := c.Param("key_id")
    if keyID == "" {
        h.respondWithError(c, http.StatusBadRequest, "API Key ID is required in path.")
        return
    }

    err := h.apiKeySvc.RevokeUserAPIKey(c.Request.Context(), userID, keyID)
    if err != nil {
        h.logger.Error("DeleteAPIKeyHandler: service error", zap.Error(err), zap.String("userID", userID), zap.String("keyID", keyID))
        if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "not owned") {
            h.respondWithError(c, http.StatusNotFound, "API Key not found or not owned by user.")
        } else {
            h.respondWithError(c, http.StatusInternalServerError, "Failed to delete API key.")
        }
        return
    }
    c.Status(http.StatusNoContent)
}


// RegisterMeRoutes registers /me related HTTP routes.
func RegisterMeRoutes(
	routerGroup *gin.RouterGroup, 
	meHandler *MeHandler, 
	authMiddleware gin.HandlerFunc, 
) {
	me := routerGroup.Group("/me")
	me.Use(authMiddleware) 
	{
		me.GET("", meHandler.GetMe)
		me.PUT("/password", meHandler.ChangePasswordHandler)
		
		sessionsGroup := me.Group("/sessions")
		{
			sessionsGroup.GET("", meHandler.ListMySessionsHandler)
			sessionsGroup.DELETE("/:session_id", meHandler.RevokeMySessionHandler)
		}
		
		apiKeysGroup := me.Group("/api-keys")
		{
			apiKeysGroup.POST("", meHandler.CreateAPIKeyHandler)
			apiKeysGroup.GET("", meHandler.ListAPIKeysHandler)
			apiKeysGroup.DELETE("/:key_id", meHandler.DeleteAPIKeyHandler)
		}
		
		mfaGroup := me.Group("/2fa")
		{
			mfaGroup.POST("/totp/enable", meHandler.Enable2FAInitiateHandler)
			mfaGroup.POST("/totp/verify", meHandler.VerifyAndActivate2FAHandler) 
			mfaGroup.POST("/disable", meHandler.Disable2FAHandler)
			mfaGroup.POST("/backup-codes/regenerate", meHandler.RegenerateBackupCodesHandler)
		}
	}
}

// Meta struct for pagination (can be shared)
type Meta struct {
	CurrentPage int `json:"current_page"`
	PerPage     int `json:"per_page"`
	TotalItems  int `json:"total_items"`
	TotalPages  int `json:"total_pages"`
}
