// File: backend/services/auth-service/internal/handler/http/external_auth_handler.go
package http

import (
	"encoding/json"
	"net/http"
	"strings" // For parsing User-Agent if needed, or client IP

	"go.uber.org/zap"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/entity" // For LoginResponse structure if defined there
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
)

// ExternalAuthHandler handles HTTP requests for external authentication (e.g., Telegram).
type ExternalAuthHandler struct {
	logger           *zap.Logger
	authLogicService service.AuthLogicService
	// Add other necessary services, like a config reader if not passed directly
}

// NewExternalAuthHandler creates a new ExternalAuthHandler.
func NewExternalAuthHandler(logger *zap.Logger, authLogic service.AuthLogicService) *ExternalAuthHandler {
	return &ExternalAuthHandler{
		logger:           logger.Named("external_auth_handler"),
		authLogicService: authLogic,
	}
}

// TelegramLoginRequest represents the expected JSON body for Telegram login.
// This mirrors the map[string]interface{} used in TelegramVerifierService,
// but a struct is better for request binding.
type TelegramLoginRequest struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name,omitempty"`
	Username  string `json:"username,omitempty"`
	PhotoURL  string `json:"photo_url,omitempty"`
	AuthDate  int64  `json:"auth_date"`
	Hash      string `json:"hash"`
	// We can add other fields if Telegram sends more that we want to capture directly.
}

// LoginResponse is a generic structure for returning tokens and user info.
// This should ideally be shared or defined in a common place if used by other handlers.
type LoginResponse struct {
	User         *entity.User `json:"user"` // Or a DTO for user info
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"` // The opaque refresh token value
	TokenType    string       `json:"token_type"`    // Usually "Bearer"
	ExpiresIn    int64        `json:"expires_in"`    // Access token expiry in seconds from now
}

// HandleTelegramLogin processes requests for authentication via Telegram.
// Path: POST /api/v1/auth/telegram-login
func (h *ExternalAuthHandler) HandleTelegramLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req TelegramLoginRequest // Or map[string]interface{} if more flexible
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondWithError(w, http.StatusBadRequest, "Invalid request payload: "+err.Error())
		return
	}
	defer r.Body.Close()

	// Convert struct to map[string]interface{} for TelegramVerifierService if it expects that
	// Or, adapt TelegramVerifierService to take a struct. For now, convert.
	telegramDataMap := make(service.TelegramAuthData)
	telegramDataMap["id"] = req.ID // Telegram sends ID as number, ensure service handles float64 or int64
	telegramDataMap["first_name"] = req.FirstName
	if req.LastName != "" {
		telegramDataMap["last_name"] = req.LastName
	}
	if req.Username != "" {
		telegramDataMap["username"] = req.Username
	}
	if req.PhotoURL != "" {
		telegramDataMap["photo_url"] = req.PhotoURL
	}
	telegramDataMap["auth_date"] = req.AuthDate // Telegram sends AuthDate as number
	telegramDataMap["hash"] = req.Hash

	// Extract IP Address and User-Agent
	ipAddress := r.RemoteAddr // This might include port, consider parsing
	// For more accurate IP, check X-Forwarded-For or X-Real-IP if behind a proxy
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		ips := strings.Split(forwardedFor, ",")
		ipAddress = strings.TrimSpace(ips[0])
	} else if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		ipAddress = realIP
	}

	userAgent := r.UserAgent()
	clientDeviceInfo := make(map[string]interface{}) // Placeholder for more detailed device info

	user, accessToken, refreshTokenValue, err := h.authLogicService.LoginWithTelegram(
		r.Context(), telegramDataMap, ipAddress, userAgent, clientDeviceInfo,
	)

	if err != nil {
		// Map domain errors to HTTP status codes
		errMsg := err.Error()
		if strings.Contains(errMsg, "invalid telegram data") || strings.Contains(errMsg, "verification failed") {
			h.respondWithError(w, http.StatusUnauthorized, "Telegram authentication failed: "+errMsg)
		} else if strings.Contains(errMsg, "user account is blocked") {
			h.respondWithError(w, http.StatusForbidden, errMsg)
		} else if strings.Contains(errMsg, "user account not active") {
			h.respondWithError(w, http.StatusForbidden, errMsg)
		} else {
			h.logger.Error("LoginWithTelegram failed", zap.Error(err))
			h.respondWithError(w, http.StatusInternalServerError, "Login failed: "+errMsg)
		}
		return
	}

	loginResp := LoginResponse{
		User:         user, // Consider a UserDTO to not expose all user fields
		AccessToken:  accessToken,
		RefreshToken: refreshTokenValue,
		TokenType:    "Bearer",
		ExpiresIn:    int(h.cfg.JWT.AccessTokenTTL.Seconds()),
	}

	h.respondWithJSON(w, http.StatusOK, loginResp)
}

func (h *ExternalAuthHandler) respondWithError(w http.ResponseWriter, code int, message string) {
	h.respondWithJSON(w, code, map[string]string{"error": message})
}

func (h *ExternalAuthHandler) respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		h.logger.Error("Failed to marshal JSON response", zap.Error(err), zap.Any("payload", payload))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"Failed to marshal response"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// How to register this handler in main.go (or router.go):
// Presuming the router setup in internal/handler/http/router.go
//
// import (
//   ...
//   externalauthhandler "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/handler/http"
//   authlogicservice "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
//   telegramverifier "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/infrastructure/security"
//   extAccRepo "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/infrastructure/database"
// )
//
// // In NewRouter or where services are initialized:
// // ...
// telegramVerifier := telegramverifier.NewTelegramVerifier()
// externalAccountRepo := extAccRepo.NewPgxExternalAccountRepository(dbPool) // Assuming dbPool is your *pgxpool.Pool
//
// // Ensure AuthLogicService's config includes these new dependencies when initialized in main.go
// // authLogicServiceConfig.ExternalAccountRepo = externalAccountRepo
// // authLogicServiceConfig.TelegramVerifier = telegramVerifier
// // authLogicServiceConfig.AppConfig = &service.SimplifiedConfigForAuthLogic{ TelegramBotToken: mainAppConfig.Telegram.BotToken }
// // authLogicService := authlogicservice.NewAuthLogicService(authLogicServiceConfig)
//
// externalAuthHandler := externalauthhandler.NewExternalAuthHandler(logger, authLogicServiceInstance)
//
// // If using Gin:
// // authGroup := router.Group("/api/v1/auth")
// // authGroup.POST("/telegram-login", gin.WrapF(externalAuthHandler.HandleTelegramLogin))
// // If using standard http.ServeMux:
// // mux.HandleFunc("/api/v1/auth/telegram-login", externalAuthHandler.HandleTelegramLogin)
//
// This provides the handler; actual registration depends on the router used in the existing setup.
