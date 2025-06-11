// File: backend/services/auth-service/tests/internal/handler/http/middleware/cors_test.go
package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/handler/http/middleware"
)

// setupTestRouter creates a gin Engine with the CorsMiddleware and a dummy handler.
func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.CorsMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	router.OPTIONS("/test", func(c *gin.Context) { // Handler for OPTIONS requests
		c.Status(http.StatusOK)
	})
	return router
}

func TestCorsDefaultNoOrigins(t *testing.T) {
	// Ensure CORS_ALLOWED_ORIGINS is not set for this test
	originalOrigins, wasSet := os.LookupEnv("CORS_ALLOWED_ORIGINS")
	if wasSet {
		os.Unsetenv("CORS_ALLOWED_ORIGINS")
	}
	t.Cleanup(func() {
		if wasSet {
			os.Setenv("CORS_ALLOWED_ORIGINS", originalOrigins)
		} else {
			os.Unsetenv("CORS_ALLOWED_ORIGINS")
		}
	})

	router := setupTestRouter()

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://disallowed.com")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	allowedOrigin := rr.Header().Get("Access-Control-Allow-Origin")
	if allowedOrigin != "" {
		// The gin-contrib/cors middleware by default allows all origins ("*") if AllowOrigins is empty.
		// However, our modification sets it to an empty list `[]string{}` if the env var is not set.
		// An empty list in gin-contrib/cors means no origins are allowed.
		// So, the header should be empty or not present.
		t.Errorf("Expected Access-Control-Allow-Origin to be empty when CORS_ALLOWED_ORIGINS is not set, but got '%s'", allowedOrigin)
	}

	// Test with an OPTIONS request as well
	reqOptions, _ := http.NewRequest("OPTIONS", "/test", nil)
	reqOptions.Header.Set("Origin", "https://disallowed.com")
	reqOptions.Header.Set("Access-Control-Request-Method", "GET")
	rrOptions := httptest.NewRecorder()
	router.ServeHTTP(rrOptions, reqOptions)

	allowedOriginOptions := rrOptions.Header().Get("Access-Control-Allow-Origin")
	if allowedOriginOptions != "" {
		t.Errorf("OPTIONS: Expected Access-Control-Allow-Origin to be empty when CORS_ALLOWED_ORIGINS is not set, but got '%s'", allowedOriginOptions)
	}
}

func TestCorsSingleAllowedOrigin(t *testing.T) {
	const allowedOriginDomain = "https://example.com"
	os.Setenv("CORS_ALLOWED_ORIGINS", allowedOriginDomain)
	t.Cleanup(func() {
		os.Unsetenv("CORS_ALLOWED_ORIGINS")
	})

	router := setupTestRouter()

	// Test with allowed origin
	reqAllowed, _ := http.NewRequest("GET", "/test", nil)
	reqAllowed.Header.Set("Origin", allowedOriginDomain)
	rrAllowed := httptest.NewRecorder()
	router.ServeHTTP(rrAllowed, reqAllowed)

	if rrAllowed.Header().Get("Access-Control-Allow-Origin") != allowedOriginDomain {
		t.Errorf("Expected Access-Control-Allow-Origin to be '%s', got '%s'",
			allowedOriginDomain, rrAllowed.Header().Get("Access-Control-Allow-Origin"))
	}

	// Test with disallowed origin
	reqDisallowed, _ := http.NewRequest("GET", "/test", nil)
	reqDisallowed.Header.Set("Origin", "https://another.com")
	rrDisallowed := httptest.NewRecorder()
	router.ServeHTTP(rrDisallowed, reqDisallowed)

	if rrDisallowed.Header().Get("Access-Control-Allow-Origin") != "" {
		// If origin is not allowed, this header should not be set or be empty.
		// Some CORS implementations might set it to "null" or the first allowed origin.
		// gin-contrib/cors with an explicit list will not set it if origin is not in the list.
		t.Errorf("Expected Access-Control-Allow-Origin to be empty for disallowed origin, got '%s'",
			rrDisallowed.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCorsMultipleAllowedOrigins(t *testing.T) {
	const origins = "https://example.com,https://test.com"
	os.Setenv("CORS_ALLOWED_ORIGINS", origins)
	t.Cleanup(func() {
		os.Unsetenv("CORS_ALLOWED_ORIGINS")
	})

	router := setupTestRouter()
	allowedOriginsList := strings.Split(origins, ",")

	// Test with first allowed origin
	reqEx, _ := http.NewRequest("GET", "/test", nil)
	reqEx.Header.Set("Origin", allowedOriginsList[0])
	rrEx := httptest.NewRecorder()
	router.ServeHTTP(rrEx, reqEx)
	if rrEx.Header().Get("Access-Control-Allow-Origin") != allowedOriginsList[0] {
		t.Errorf("Expected Access-Control-Allow-Origin to be '%s', got '%s'",
			allowedOriginsList[0], rrEx.Header().Get("Access-Control-Allow-Origin"))
	}

	// Test with second allowed origin
	reqTest, _ := http.NewRequest("GET", "/test", nil)
	reqTest.Header.Set("Origin", allowedOriginsList[1])
	rrTest := httptest.NewRecorder()
	router.ServeHTTP(rrTest, reqTest)
	if rrTest.Header().Get("Access-Control-Allow-Origin") != allowedOriginsList[1] {
		t.Errorf("Expected Access-Control-Allow-Origin to be '%s', got '%s'",
			allowedOriginsList[1], rrTest.Header().Get("Access-Control-Allow-Origin"))
	}

	// Test with disallowed origin
	reqAnother, _ := http.NewRequest("GET", "/test", nil)
	reqAnother.Header.Set("Origin", "https://another.com")
	rrAnother := httptest.NewRecorder()
	router.ServeHTTP(rrAnother, reqAnother)
	if rrAnother.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("Expected Access-Control-Allow-Origin to be empty for disallowed origin, got '%s'",
			rrAnother.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCorsAllowedMethodAndHeaders(t *testing.T) {
	const allowedOriginDomain = "https://example.com"
	os.Setenv("CORS_ALLOWED_ORIGINS", allowedOriginDomain)
	t.Cleanup(func() {
		os.Unsetenv("CORS_ALLOWED_ORIGINS")
	})

	router := setupTestRouter()

	// Test preflight request for methods and headers
	req, _ := http.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", allowedOriginDomain)
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type, X-CSRF-Token")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Check Allow-Origin for preflight
	if rr.Header().Get("Access-Control-Allow-Origin") != allowedOriginDomain {
		t.Errorf("Preflight: Expected Access-Control-Allow-Origin to be '%s', got '%s'",
			allowedOriginDomain, rr.Header().Get("Access-Control-Allow-Origin"))
	}

	// Check Allow-Methods
	allowMethods := rr.Header().Get("Access-Control-Allow-Methods")
	expectedMethods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} // From cors.go
	for _, method := range expectedMethods {
		if !strings.Contains(allowMethods, method) {
			t.Errorf("Expected Access-Control-Allow-Methods to contain '%s', got '%s'", method, allowMethods)
		}
	}
	if !strings.Contains(allowMethods, "POST") { // Specifically check the requested method
		t.Errorf("Expected Access-Control-Allow-Methods to contain 'POST', got '%s'", allowMethods)
	}

	// Check Allow-Headers
	allowHeaders := rr.Header().Get("Access-Control-Allow-Headers")
	// Headers from cors.go that were requested:
	expectedHeaders := []string{"Authorization", "Content-Type", "X-CSRF-Token"}
	for _, header := range expectedHeaders {
		if !strings.Contains(allowHeaders, header) {
			t.Errorf("Expected Access-Control-Allow-Headers to contain '%s', got '%s'", header, allowHeaders)
		}
	}
}

func TestCorsCredentialsAllowed(t *testing.T) {
	const allowedOriginDomain = "https://example.com"
	os.Setenv("CORS_ALLOWED_ORIGINS", allowedOriginDomain)
	t.Cleanup(func() {
		os.Unsetenv("CORS_ALLOWED_ORIGINS")
	})

	router := setupTestRouter()

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", allowedOriginDomain)
	// For credentials to be allowed, the request often includes cookies or Authorization header.
	// However, the server setting `Access-Control-Allow-Credentials: true` is unconditional
	// in the current middleware setup if AllowCredentials is true.
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Check Allow-Origin first (as a sanity check that the request was processed by CORS correctly)
	if rr.Header().Get("Access-Control-Allow-Origin") != allowedOriginDomain {
		t.Errorf("CredentialsTest: Expected Access-Control-Allow-Origin to be '%s', got '%s'",
			allowedOriginDomain, rr.Header().Get("Access-Control-Allow-Origin"))
	}

	// Check Allow-Credentials
	if rr.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("Expected Access-Control-Allow-Credentials to be 'true', got '%s'",
			rr.Header().Get("Access-Control-Allow-Credentials"))
	}
}

// TestCorsWildcardOrigin tests the scenario where "*" is explicitly set.
// Note: The current implementation of CorsMiddleware in cors.go defaults to an empty list `[]string{}`
// if CORS_ALLOWED_ORIGINS is not set or empty, which effectively means no origins allowed.
// If CORS_ALLOWED_ORIGINS="*", then gin-contrib/cors should handle it as wildcard.
func TestCorsWildcardOrigin(t *testing.T) {
	os.Setenv("CORS_ALLOWED_ORIGINS", "*")
	t.Cleanup(func() {
		os.Unsetenv("CORS_ALLOWED_ORIGINS")
	})

	router := setupTestRouter()

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://anything.com")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// When AllowOrigins is ["*"] and AllowCredentials is true, the server must respond
	// with the specific requesting origin, not "*".
	// However, the current CorsMiddleware sets AllowOrigins directly.
	// If AllowOrigins = []string{"*"}, gin-contrib/cors handles this by setting ACAO to "*".
	// If AllowCredentials = true, and ACAO is "*", this is an invalid CORS configuration.
	// Let's test current behavior. The middleware has AllowCredentials: true.
	// The gin-contrib/cors library should handle this correctly:
	// If AllowOrigins is ["*"] and AllowCredentials is true, it will reflect the origin.
	// If AllowOrigins is ["foo", "bar"] and AllowCredentials is true, it reflects matching origin.

	// Based on gin-contrib/cors logic: if cfg.AllowAllOrigins is true (which happens if AllowOrigins = ["*"])
	// AND cfg.AllowCredentials is true, it should reflect the request Origin.
	// Let's verify this specific interaction.

	// The current code sets:
	// AllowOrigins: strings.Split(originsStr, ",") -> so if "CORS_ALLOWED_ORIGINS=*", then AllowOrigins = []string{"*"}
	// AllowCredentials: true
	// According to RFC1918 and gin-contrib/cors behavior:
	// If `Access-Control-Allow-Credentials` is `true`, the `Access-Control-Allow-Origin` header
	// *cannot* be a wildcard (`*`). It must be the specific origin that made the request.
	// The gin-contrib/cors library handles this: if `AllowAllOrigins` is true (derived from `AllowOrigins` containing `*`)
	// AND `AllowCredentials` is true, it will correctly set `Access-Control-Allow-Origin` to the request's `Origin` header.

	expectedOrigin := "https://anything.com" // Should reflect the requesting origin
	if rr.Header().Get("Access-Control-Allow-Origin") != expectedOrigin {
		t.Errorf("Expected Access-Control-Allow-Origin to be '%s' when CORS_ALLOWED_ORIGINS is '*' and AllowCredentials is true, got '%s'",
			expectedOrigin, rr.Header().Get("Access-Control-Allow-Origin"))
	}
	if rr.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("Expected Access-Control-Allow-Credentials to be 'true', got '%s'",
			rr.Header().Get("Access-Control-Allow-Credentials"))
	}
}
