// File: backend/services/auth-service/internal/handler/http/jwks_handler.go
package http

import (
	"encoding/json"
	"net/http"

	"github.com/your-org/auth-service/internal/domain/service" // For TokenManagementService
	"go.uber.org/zap"
)

// JWKSHandler handles requests for the JSON Web Key Set (JWKS).
type JWKSHandler struct {
	tokenManager service.TokenManagementService
	logger       *zap.Logger
}

// NewJWKSHandler creates a new JWKSHandler.
func NewJWKSHandler(tokenManager service.TokenManagementService, logger *zap.Logger) *JWKSHandler {
	return &JWKSHandler{
		tokenManager: tokenManager,
		logger:       logger.Named("jwks_handler"),
	}
}

// GetJWKS serves the JWKS endpoint.
// It retrieves the public keys from the TokenManagementService and returns them in JWKS format.
// Path: /.well-known/jwks.json OR /api/v1/auth/jwks.json
func (h *JWKSHandler) GetJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ErrorResponse(w, h.logger, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}

	jwks, err := h.tokenManager.GetJWKS()
	if err != nil {
		h.logger.Error("Failed to get JWKS from token manager", zap.Error(err))
		ErrorResponse(w, h.logger, http.StatusInternalServerError, "Failed to retrieve JWKS", nil)
		return
	}

	w.Header().Set("Content-Type", "application/jwk-set+json") // Standard content type for JWKS
	w.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate") // Cache for 1 hour

	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		h.logger.Error("Failed to write JWKS response", zap.Error(err))
		// Response might be partially written, so can't send another ErrorResponse easily.
	}
}
