// File: internal/utils/device/device.go

package device

import (
	"net/http"
	"strings"

	"github.com/mssola/user_agent"
)

// Info содержит информацию об устройстве пользователя
type Info struct {
	Browser        string `json:"browser"`
	BrowserVersion string `json:"browser_version"`
	OS             string `json:"os"`
	OSVersion      string `json:"os_version"`
	DeviceType     string `json:"device_type"`
	IsMobile       bool   `json:"is_mobile"`
	IsTablet       bool   `json:"is_tablet"`
	IsBot          bool   `json:"is_bot"`
	UserAgent      string `json:"user_agent"`
}

// DeviceType представляет тип устройства
type DeviceType string

const (
	// Desktop представляет настольный компьютер
	Desktop DeviceType = "desktop"
	// Mobile представляет мобильное устройство
	Mobile DeviceType = "mobile"
	// Tablet представляет планшет
	Tablet DeviceType = "tablet"
	// Bot представляет бота
	Bot DeviceType = "bot"
	// Unknown представляет неизвестное устройство
	Unknown DeviceType = "unknown"
)

// GetDeviceInfo извлекает информацию об устройстве из HTTP-запроса
func GetDeviceInfo(r *http.Request) *Info {
	userAgentString := r.UserAgent()
	ua := user_agent.New(userAgentString)

	// Получаем информацию о браузере
	browserName, browserVersion := ua.Browser()

	// Получаем информацию об ОС
	os := ua.OS()
	osInfo := strings.Split(os, " ")
	osName := osInfo[0]
	osVersion := ""
	if len(osInfo) > 1 {
		osVersion = strings.Join(osInfo[1:], " ")
	}

	// Определяем тип устройства
	deviceType := Desktop
	isMobile := ua.Mobile()
	isBot := ua.Bot()
	isTablet := false

	// Проверяем, является ли устройство планшетом
	if strings.Contains(strings.ToLower(userAgentString), "tablet") ||
		strings.Contains(strings.ToLower(userAgentString), "ipad") {
		isTablet = true
		deviceType = Tablet
	} else if isMobile {
		deviceType = Mobile
	} else if isBot {
		deviceType = Bot
	}

	return &Info{
		Browser:        browserName,
		BrowserVersion: browserVersion,
		OS:             osName,
		OSVersion:      osVersion,
		DeviceType:     string(deviceType),
		IsMobile:       isMobile,
		IsTablet:       isTablet,
		IsBot:          isBot,
		UserAgent:      userAgentString,
	}
}

// FormatDeviceInfo форматирует информацию об устройстве в читаемый вид
func FormatDeviceInfo(info *Info) string {
	if info == nil {
		return "Unknown Device"
	}

	// Формируем строку с информацией об устройстве
	var deviceInfo string

	// Добавляем информацию о браузере
	if info.Browser != "" {
		deviceInfo = info.Browser
		if info.BrowserVersion != "" {
			deviceInfo += " " + info.BrowserVersion
		}
	}

	// Добавляем информацию об ОС
	if info.OS != "" {
		if deviceInfo != "" {
			deviceInfo += " on "
		}
		deviceInfo += info.OS
		if info.OSVersion != "" {
			deviceInfo += " " + info.OSVersion
		}
	}

	// Добавляем тип устройства
	if info.DeviceType != "" && info.DeviceType != string(Desktop) {
		deviceInfo += " (" + info.DeviceType + ")"
	}

	// Если не удалось получить информацию, возвращаем "Unknown Device"
	if deviceInfo == "" {
		return "Unknown Device"
	}

	return deviceInfo
}

// IsSuspiciousDevice проверяет, является ли устройство подозрительным
func IsSuspiciousDevice(info *Info) bool {
	if info == nil {
		return true
	}

	// Проверяем, является ли устройство ботом
	if info.IsBot {
		return true
	}

	// Проверяем наличие подозрительных строк в User-Agent
	suspiciousStrings := []string{
		"curl",
		"wget",
		"python-requests",
		"python-urllib",
		"java/",
		"apache-httpclient",
		"go-http-client",
		"scrapy",
		"phantomjs",
		"headless",
		"selenium",
		"puppeteer",
	}

	for _, s := range suspiciousStrings {
		if strings.Contains(strings.ToLower(info.UserAgent), strings.ToLower(s)) {
			return true
		}
	}

	return false
}

// CompareDeviceInfo сравнивает две информации об устройстве и возвращает уровень схожести (0-100%)
func CompareDeviceInfo(info1, info2 *Info) int {
	if info1 == nil || info2 == nil {
		return 0
	}

	// Начальный уровень схожести
	similarity := 0
	totalFactors := 5

	// Сравниваем браузер
	if strings.EqualFold(info1.Browser, info2.Browser) {
		similarity += 1
		// Если версии браузера совпадают, добавляем дополнительные баллы
		if strings.EqualFold(info1.BrowserVersion, info2.BrowserVersion) {
			similarity += 1
		}
	}

	// Сравниваем ОС
	if strings.EqualFold(info1.OS, info2.OS) {
		similarity += 1
		// Если версии ОС совпадают, добавляем дополнительные баллы
		if strings.EqualFold(info1.OSVersion, info2.OSVersion) {
			similarity += 1
		}
	}

	// Сравниваем тип устройства
	if strings.EqualFold(info1.DeviceType, info2.DeviceType) {
		similarity += 1
	}

	// Вычисляем процент схожести
	return (similarity * 100) / totalFactors
}
