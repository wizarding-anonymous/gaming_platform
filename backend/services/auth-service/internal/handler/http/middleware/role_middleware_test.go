package middleware_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/handler/http/middleware"
	"go.uber.org/zap"
)

// GinContextRolesKey is the key used by AuthMiddleware to store user roles in context.
// This needs to match the unexported constant in the actual middleware package.
// Based on comments in role_middleware.go, assuming "roles".
const GinContextRolesKey = "roles"

// Helper to setup router, apply context-setting middleware (optional), and RoleMiddleware
func setupRoleTestRouter(userRolesInContext interface{}, requiredRoles []string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	router := gin.New()

	// Middleware to set roles in context if userRolesInContext is not nil
	if userRolesInContext != nil {
		router.Use(func(c *gin.Context) {
			c.Set(GinContextRolesKey, userRolesInContext)
			c.Next()
		})
	}

	roleAuthMiddleware := middleware.RoleMiddleware(requiredRoles, logger)
	router.Use(roleAuthMiddleware)

	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "passed"})
	})
	return router
}

// ErrorFormat matches the gin.H{"error": message} structure used in the middleware
type ErrorFormat struct {
	Error string `json:"error"`
}

func TestRoleMiddleware_NoRolesRequired(t *testing.T) {
	router := setupRoleTestRouter(nil, []string{}) // No roles in context, no roles required

	req, _ := http.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var respBody map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Equal(t, "passed", respBody["message"])
}

func TestRoleMiddleware_RolesNotInContext(t *testing.T) {
	router := setupRoleTestRouter(nil, []string{"admin"}) // Roles required, but not set in context

	req, _ := http.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	var errResp ErrorFormat
	err := json.Unmarshal(rr.Body.Bytes(), &errResp)
	assert.NoError(t, err)
	assert.Equal(t, "Access denied: user roles not available", errResp.Error)
}

func TestRoleMiddleware_RolesInContext_WrongType(t *testing.T) {
	// Set roles in context with an incorrect type (e.g., int)
	router := setupRoleTestRouter(123, []string{"admin"})

	req, _ := http.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	var errResp ErrorFormat
	err := json.Unmarshal(rr.Body.Bytes(), &errResp)
	assert.NoError(t, err)
	assert.Equal(t, "Internal server error: role processing failed", errResp.Error)
}

func TestRoleMiddleware_UserHasRequiredRole_Single(t *testing.T) {
	userRoles := []string{"editor"}
	required := []string{"editor"}
	router := setupRoleTestRouter(userRoles, required)

	req, _ := http.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRoleMiddleware_UserHasRequiredRole_MultipleUserRoles(t *testing.T) {
	userRoles := []string{"user", "editor", "viewer"}
	required := []string{"editor"}
	router := setupRoleTestRouter(userRoles, required)

	req, _ := http.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRoleMiddleware_UserHasRequiredRole_MultipleRequired_UserHasOne(t *testing.T) {
	userRoles := []string{"editor"}
	required := []string{"admin", "editor"}
	router := setupRoleTestRouter(userRoles, required)

	req, _ := http.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRoleMiddleware_UserHasRequiredRole_MultipleRequired_UserHasAnother(t *testing.T) {
	userRoles := []string{"user", "admin"}
	required := []string{"admin", "editor"}
	router := setupRoleTestRouter(userRoles, required)

	req, _ := http.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRoleMiddleware_UserDoesNotHaveRequiredRole(t *testing.T) {
	userRoles := []string{"viewer", "user"}
	required := []string{"admin", "editor"}
	router := setupRoleTestRouter(userRoles, required)

	req, _ := http.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	var errResp ErrorFormat
	err := json.Unmarshal(rr.Body.Bytes(), &errResp)
	assert.NoError(t, err)
	assert.Equal(t, "Access denied: insufficient permissions", errResp.Error)
}

func TestRoleMiddleware_UserHasNoRoles_RequiredAreSet(t *testing.T) {
	userRoles := []string{} // User has an empty list of roles
	required := []string{"admin"}
	router := setupRoleTestRouter(userRoles, required)

	req, _ := http.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	var errResp ErrorFormat
	err := json.Unmarshal(rr.Body.Bytes(), &errResp)
	assert.NoError(t, err)
	assert.Equal(t, "Access denied: insufficient permissions", errResp.Error)
}

func TestRoleMiddleware_UserHasRole_RequiredIsEmpty(t *testing.T) {
	// This is covered by TestRoleMiddleware_NoRolesRequired, but good for clarity
	userRoles := []string{"admin"}
	required := []string{} // No roles required
	router := setupRoleTestRouter(userRoles, required)

	req, _ := http.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}
