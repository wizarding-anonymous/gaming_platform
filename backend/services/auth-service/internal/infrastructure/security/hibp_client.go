// File: backend/services/auth-service/internal/infrastructure/security/hibp_client.go
package security

import (
	"bufio"
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"net" // Added for net.Error check
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"                             // For config.HIBPConfig
	domainInterfaces "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/interfaces" // For domainInterfaces.HIBPService
	"go.uber.org/zap"
)

const hibpRequestTimeout = 5 * time.Second

// HIBPClient implements the domainInterfaces.HIBPService interface.
type HIBPClient struct {
	httpClient *http.Client
	userAgent  string
	logger     *zap.Logger
}

// NewHIBPClient creates a new HIBP client.
func NewHIBPClient(cfg config.HIBPConfig, logger *zap.Logger) *HIBPClient { // Return concrete type
	return &HIBPClient{
		httpClient: &http.Client{
			Timeout: hibpRequestTimeout,
		},
		userAgent: cfg.UserAgent,
		logger:    logger.Named("hibp_client"),
	}
}

// CheckPasswordPwned implements the HIBPService interface.
// Returns pwned status (bool), count of times pwned (int), and error.
func (c *HIBPClient) CheckPasswordPwned(ctx context.Context, password string) (bool, int, error) {
	if password == "" {
		return false, 0, fmt.Errorf("password cannot be empty")
	}

	h := sha1.New()
	if _, err := io.WriteString(h, password); err != nil {
		c.logger.Error("Failed to write password to hasher", zap.Error(err))
		return false, 0, fmt.Errorf("failed to hash password: %w", err)
	}
	hash := fmt.Sprintf("%X", h.Sum(nil))

	prefix := hash[:5]
	suffix := hash[5:]

	apiURL := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		c.logger.Error("Failed to create HIBP API request", zap.Error(err), zap.String("url", apiURL))
		return false, 0, fmt.Errorf("failed to create HIBP request: %w", err)
	}

	ua := c.userAgent
	if ua == "" {
		ua = "AuthServiceHIBPChecker/1.0" // Default User-Agent
		c.logger.Info("HIBP User-Agent not configured, using default.", zap.String("defaultUserAgent", ua))
	}
	req.Header.Set("User-Agent", ua)
	// req.Header.Set("Add-Padding", "true") // Optional: For additional privacy

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Check for context cancellation or timeout
		if ctx.Err() == context.Canceled {
			c.logger.Warn("HIBP request cancelled by context", zap.String("url", apiURL), zap.Error(ctx.Err()))
			return false, 0, fmt.Errorf("HIBP request cancelled: %w", ctx.Err())
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			c.logger.Warn("HIBP request timed out", zap.String("url", apiURL), zap.Error(err))
			return false, 0, fmt.Errorf("HIBP request timed out: %w", err)
		}
		c.logger.Error("HIBP API request failed", zap.Error(err), zap.String("url", apiURL))
		return false, 0, fmt.Errorf("HIBP API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body) // Ignoring error from ReadAll for error reporting
		c.logger.Error("HIBP API returned non-OK status",
			zap.Int("status_code", resp.StatusCode),
			zap.String("url", apiURL),
			zap.ByteString("response_body", bodyBytes),
		)
		return false, 0, fmt.Errorf("HIBP API returned status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			c.logger.Warn("Unexpected line format from HIBP API", zap.String("line", line))
			continue
		}
		if strings.EqualFold(parts[0], suffix) {
			count, convErr := strconv.Atoi(parts[1])
			if convErr != nil {
				c.logger.Error("Failed to convert HIBP count to int", zap.Error(convErr), zap.String("suffix_match", parts[0]), zap.String("count_str", parts[1]))
				return true, 0, fmt.Errorf("failed to parse pwned count: %w", convErr)
			}
			c.logger.Info("Password hash suffix found in HIBP database", zap.String("prefix", prefix), zap.String("suffix_match", parts[0]), zap.Int("count", count))
			return true, count, nil
		}
	}

	if err := scanner.Err(); err != nil {
		c.logger.Error("Error reading HIBP API response body", zap.Error(err))
		return false, 0, fmt.Errorf("error reading HIBP response: %w", err)
	}

	c.logger.Debug("Password hash suffix not found in HIBP database for prefix", zap.String("prefix", prefix))
	return false, 0, nil
}

// Ensure HIBPClient implements HIBPService interface
var _ domainInterfaces.HIBPService = (*HIBPClient)(nil)
