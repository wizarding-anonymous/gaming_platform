// File: backend/services/auth-service/internal/utils/ip/ip.go

package ip

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/logger"
)

// GeoInfo содержит информацию о геолокации IP-адреса
type GeoInfo struct {
	IP          string  `json:"ip"`
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	RegionCode  string  `json:"region_code"`
	RegionName  string  `json:"region_name"`
	City        string  `json:"city"`
	ZipCode     string  `json:"zip_code"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	TimeZone    string  `json:"time_zone"`
}

// Service представляет сервис для работы с IP-адресами
type Service struct {
	config *config.IPConfig
	logger logger.Logger
	client *http.Client
}

// NewService создает новый сервис для работы с IP-адресами
func NewService(config *config.IPConfig, logger logger.Logger) *Service {
	return &Service{
		config: config,
		logger: logger,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// ExtractIP извлекает IP-адрес из HTTP-запроса
func (s *Service) ExtractIP(r *http.Request) string {
	// Проверяем заголовки, которые могут содержать реальный IP клиента
	for _, header := range s.config.TrustedHeaders {
		if ip := r.Header.Get(header); ip != "" {
			// Если заголовок содержит список IP-адресов, берем первый
			if strings.Contains(ip, ",") {
				return strings.TrimSpace(strings.Split(ip, ",")[0])
			}
			return strings.TrimSpace(ip)
		}
	}

	// Если заголовки не содержат IP, извлекаем из RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// Если не удалось разделить, возвращаем как есть
		return r.RemoteAddr
	}
	return ip
}

// IsPrivate проверяет, является ли IP-адрес приватным
func (s *Service) IsPrivate(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Проверяем, является ли IP приватным
	privateIPBlocks := []string{
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"127.0.0.0/8",    // RFC1122 Section 3.2.1.3
		"169.254.0.0/16", // RFC3927
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	}

	for _, block := range privateIPBlocks {
		_, subnet, err := net.ParseCIDR(block)
		if err != nil {
			continue
		}
		if subnet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// GetGeoInfo получает информацию о геолокации IP-адреса
func (s *Service) GetGeoInfo(ctx context.Context, ip string) (*GeoInfo, error) {
	// Проверяем, является ли IP приватным
	if s.IsPrivate(ip) {
		return &GeoInfo{
			IP:          ip,
			CountryCode: "XX",
			CountryName: "Local Network",
			City:        "Local",
			TimeZone:    "UTC",
		}, nil
	}

	// Если геолокация отключена, возвращаем базовую информацию
	if !s.config.GeoEnabled {
		return &GeoInfo{
			IP: ip,
		}, nil
	}

	// Формируем URL для запроса к API геолокации
	url := fmt.Sprintf("%s/%s", s.config.GeoAPIURL, ip)

	// Создаем запрос
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		s.logger.Error("Failed to create geo request", "error", err, "ip", ip)
		return nil, err
	}

	// Добавляем заголовки авторизации, если они настроены
	if s.config.GeoAPIKey != "" {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", s.config.GeoAPIKey))
	}

	// Выполняем запрос
	resp, err := s.client.Do(req)
	if err != nil {
		s.logger.Error("Failed to get geo info", "error", err, "ip", ip)
		return nil, err
	}
	defer resp.Body.Close()

	// Проверяем статус ответа
	if resp.StatusCode != http.StatusOK {
		s.logger.Error("Geo API returned non-OK status", "status", resp.StatusCode, "ip", ip)
		return nil, fmt.Errorf("geo API returned status %d", resp.StatusCode)
	}

	// Декодируем ответ
	var geoInfo GeoInfo
	if err := json.NewDecoder(resp.Body).Decode(&geoInfo); err != nil {
		s.logger.Error("Failed to decode geo response", "error", err, "ip", ip)
		return nil, err
	}

	return &geoInfo, nil
}

// IsCountryAllowed проверяет, разрешена ли страна
func (s *Service) IsCountryAllowed(countryCode string) bool {
	// Если список разрешенных стран пуст, разрешаем все
	if len(s.config.AllowedCountries) == 0 {
		return true
	}

	// Проверяем, есть ли страна в списке разрешенных
	for _, allowed := range s.config.AllowedCountries {
		if strings.EqualFold(allowed, countryCode) {
			return true
		}
	}

	return false
}

// IsCountryBlocked проверяет, заблокирована ли страна
func (s *Service) IsCountryBlocked(countryCode string) bool {
	// Проверяем, есть ли страна в списке заблокированных
	for _, blocked := range s.config.BlockedCountries {
		if strings.EqualFold(blocked, countryCode) {
			return true
		}
	}

	return false
}

// CheckAccess проверяет, разрешен ли доступ для IP-адреса
func (s *Service) CheckAccess(ctx context.Context, ip string) (bool, string, error) {
	// Если проверка доступа отключена, разрешаем доступ
	if !s.config.AccessCheckEnabled {
		return true, "", nil
	}

	// Если IP приватный, разрешаем доступ
	if s.IsPrivate(ip) {
		return true, "", nil
	}

	// Получаем информацию о геолокации
	geoInfo, err := s.GetGeoInfo(ctx, ip)
	if err != nil {
		// В случае ошибки, если настроено разрешать доступ при ошибках, разрешаем
		if s.config.AllowOnError {
			s.logger.Warn("Failed to get geo info, allowing access", "error", err, "ip", ip)
			return true, "", err
		}
		return false, "Failed to determine location", err
	}

	// Проверяем, заблокирована ли страна
	if s.IsCountryBlocked(geoInfo.CountryCode) {
		s.logger.Warn("Access blocked: country is in blocklist", "ip", ip, "country", geoInfo.CountryCode)
		return false, fmt.Sprintf("Access from %s is not allowed", geoInfo.CountryName), nil
	}

	// Проверяем, разрешена ли страна
	if !s.IsCountryAllowed(geoInfo.CountryCode) {
		s.logger.Warn("Access blocked: country is not in allowlist", "ip", ip, "country", geoInfo.CountryCode)
		return false, fmt.Sprintf("Access from %s is not allowed", geoInfo.CountryName), nil
	}

	return true, "", nil
}

// FormatLocation форматирует местоположение на основе информации о геолокации
func (s *Service) FormatLocation(geoInfo *GeoInfo) string {
	if geoInfo == nil {
		return "Unknown"
	}

	// Формируем строку местоположения
	parts := []string{}

	if geoInfo.City != "" {
		parts = append(parts, geoInfo.City)
	}

	if geoInfo.RegionName != "" {
		parts = append(parts, geoInfo.RegionName)
	}

	if geoInfo.CountryName != "" {
		parts = append(parts, geoInfo.CountryName)
	}

	if len(parts) == 0 {
		return "Unknown"
	}

	return strings.Join(parts, ", ")
}
