// File: internal/utils/time/time.go

package time

import (
	"fmt"
	"time"
)

// TimeZones содержит список поддерживаемых часовых поясов
var TimeZones = map[string]string{
	"UTC":       "UTC",
	"MSK":       "Europe/Moscow",
	"Europe":    "Europe/Berlin",
	"US/East":   "America/New_York",
	"US/West":   "America/Los_Angeles",
	"Asia":      "Asia/Tokyo",
	"Australia": "Australia/Sydney",
}

// FormatTime форматирует время в указанном формате
func FormatTime(t time.Time, format string) string {
	switch format {
	case "iso":
		return t.Format(time.RFC3339)
	case "date":
		return t.Format("2006-01-02")
	case "time":
		return t.Format("15:04:05")
	case "datetime":
		return t.Format("2006-01-02 15:04:05")
	case "rfc822":
		return t.Format(time.RFC822)
	case "rfc850":
		return t.Format(time.RFC850)
	case "rfc1123":
		return t.Format(time.RFC1123)
	case "unix":
		return fmt.Sprintf("%d", t.Unix())
	default:
		return t.Format(format)
	}
}

// ParseTime парсит время из строки в указанном формате
func ParseTime(timeStr, format string) (time.Time, error) {
	switch format {
	case "iso":
		return time.Parse(time.RFC3339, timeStr)
	case "date":
		return time.Parse("2006-01-02", timeStr)
	case "time":
		return time.Parse("15:04:05", timeStr)
	case "datetime":
		return time.Parse("2006-01-02 15:04:05", timeStr)
	case "rfc822":
		return time.Parse(time.RFC822, timeStr)
	case "rfc850":
		return time.Parse(time.RFC850, timeStr)
	case "rfc1123":
		return time.Parse(time.RFC1123, timeStr)
	case "unix":
		var unix int64
		_, err := fmt.Sscanf(timeStr, "%d", &unix)
		if err != nil {
			return time.Time{}, fmt.Errorf("failed to parse unix timestamp: %w", err)
		}
		return time.Unix(unix, 0), nil
	default:
		return time.Parse(format, timeStr)
	}
}

// ConvertTimeZone конвертирует время из одного часового пояса в другой
func ConvertTimeZone(t time.Time, fromTZ, toTZ string) (time.Time, error) {
	// Получаем локацию исходного часового пояса
	fromLoc, err := time.LoadLocation(fromTZ)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to load source timezone: %w", err)
	}

	// Получаем локацию целевого часового пояса
	toLoc, err := time.LoadLocation(toTZ)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to load target timezone: %w", err)
	}

	// Конвертируем время
	return t.In(fromLoc).In(toLoc), nil
}

// GetTimeZoneOffset возвращает смещение часового пояса относительно UTC в секундах
func GetTimeZoneOffset(tz string) (int, error) {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return 0, fmt.Errorf("failed to load timezone: %w", err)
	}

	// Получаем текущее время в указанном часовом поясе
	now := time.Now().In(loc)

	// Получаем смещение в секундах
	_, offset := now.Zone()

	return offset, nil
}

// GetTimeZoneName возвращает название часового пояса
func GetTimeZoneName(tz string) (string, error) {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return "", fmt.Errorf("failed to load timezone: %w", err)
	}

	// Получаем текущее время в указанном часовом поясе
	now := time.Now().In(loc)

	// Получаем название часового пояса
	name, _ := now.Zone()

	return name, nil
}

// IsExpired проверяет, истекло ли время
func IsExpired(t time.Time) bool {
	return t.Before(time.Now())
}

// TimeUntil возвращает время до указанного момента
func TimeUntil(t time.Time) time.Duration {
	return time.Until(t)
}

// TimeSince возвращает время с указанного момента
func TimeSince(t time.Time) time.Duration {
	return time.Since(t)
}

// AddDuration добавляет продолжительность к времени
func AddDuration(t time.Time, duration time.Duration) time.Time {
	return t.Add(duration)
}

// FormatDuration форматирует продолжительность в удобочитаемый вид
func FormatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%d дн. %d ч. %d мин. %d сек.", days, hours, minutes, seconds)
	} else if hours > 0 {
		return fmt.Sprintf("%d ч. %d мин. %d сек.", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%d мин. %d сек.", minutes, seconds)
	} else {
		return fmt.Sprintf("%d сек.", seconds)
	}
}

// ParseDuration парсит продолжительность из строки
func ParseDuration(durationStr string) (time.Duration, error) {
	return time.ParseDuration(durationStr)
}

// GetStartOfDay возвращает начало дня для указанного времени
func GetStartOfDay(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, t.Location())
}

// GetEndOfDay возвращает конец дня для указанного времени
func GetEndOfDay(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, 23, 59, 59, 999999999, t.Location())
}

// GetStartOfMonth возвращает начало месяца для указанного времени
func GetStartOfMonth(t time.Time) time.Time {
	year, month, _ := t.Date()
	return time.Date(year, month, 1, 0, 0, 0, 0, t.Location())
}

// GetEndOfMonth возвращает конец месяца для указанного времени
func GetEndOfMonth(t time.Time) time.Time {
	year, month, _ := t.Date()
	// Получаем первый день следующего месяца и вычитаем 1 наносекунду
	return time.Date(year, month+1, 1, 0, 0, 0, 0, t.Location()).Add(-time.Nanosecond)
}
