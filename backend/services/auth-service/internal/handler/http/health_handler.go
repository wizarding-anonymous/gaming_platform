// File: backend/services/auth-service/internal/handler/http/health_handler.go
package http

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
)

// HealthHandler handles HTTP health check requests.
type HealthHandler struct {
	logger *zap.Logger
}

// NewHealthHandler creates a new HealthHandler.
// The logger is passed for potential future use (e.g., logging health check access).
func NewHealthHandler(logger *zap.Logger) *HealthHandler {
	return &HealthHandler{
		logger: logger.Named("http_health_handler"),
	}
}

// ServeHTTP responds to the health check request.
// It writes a JSON response with {"status": "SERVING"}.
func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{"status": "SERVING"}
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to write health check response", zap.Error(err))
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
	}
}

// RegisterHealthRoutes registers the /health route.
// This function can be called to add the health check endpoint to a router.
// For example, if using Gin router:
// func RegisterHealthRoutes(router *gin.Engine, logger *zap.Logger) {
//	 healthHandler := NewHealthHandler(logger)
//	 router.GET("/health", gin.WrapF(healthHandler.ServeHTTP))
// }
// Or with standard http.ServeMux:
// func RegisterHealthRoutes(mux *http.ServeMux, logger *zap.Logger) {
// 	healthHandler := NewHealthHandler(logger)
// 	mux.Handle("/health", healthHandler)
// }
// The actual registration will depend on how routes are managed in main.go or a dedicated router setup.
// For now, this provides the handler. The main.go uses its own router setup (httpHandler.NewRouter)
// so this handler would need to be integrated there.
// The subtask asks to create the handler, actual integration into the existing router in main.go
// is a further step that might require modifying main.go or the router setup files.
// Given the complexity of main.go, I will focus on providing the handler as requested.

// Note: The existing main.go uses httpHandler.NewRouter(...).
// To integrate this, one would typically:
// 1. Modify httpHandler.NewRouter or a relevant sub-router to include this.
// 2. Potentially add a method to HealthHandler to return an http.HandlerFunc if that's what the router expects.
// Example (if router expects http.HandlerFunc):
// func (h *HealthHandler) HealthCheckHandleFunc(w http.ResponseWriter, r *http.Request) {
//	 w.Header().Set("Content-Type", "application/json")
//	 response := map[string]string{"status": "SERVING"}
//	 if err := json.NewEncoder(w).Encode(response); err != nil {
//		 h.logger.Error("Failed to write health check response", zap.Error(err))
//	 }
// }
// And then register it like: router.HandleFunc("/health", healthHandler.HealthCheckHandleFunc)
// For now, the standard ServeHTTP interface is implemented.
// The subtask asks for the handler, integration into the existing complex main.go is a separate concern.
// The existing router is in `internal/handler/http/router.go` (not read yet, but assumed from main.go context)
// and it likely uses a framework like Gin or similar.
// This file just provides the basic handler logic.
// The existing main.go instantiates its router using:
// router := httpHandler.NewRouter(authService, userService, ..., cfg, logger)
// This health handler should be registered within that NewRouter function or on the router it returns.
// For example, if httpHandler.NewRouter returns a *gin.Engine:
// in httpHandler/router.go:
//   healthHandler := NewHealthHandler(logger) // or pass logger to NewHealthHandler
//   router.GET("/health", gin.WrapF(healthHandler.ServeHTTP))
// Or if it returns an http.ServeMux:
//   healthHandler := NewHealthHandler(logger)
//   router.Handle("/health", healthHandler)
// This specific file fulfills the creation of health_handler.go.