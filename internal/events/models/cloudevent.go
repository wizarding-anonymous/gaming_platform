// File: internal/events/models/cloudevent.go
package models

import (
	"encoding/json"
	"time"
)

// CloudEventSpecVersion is the CloudEvents spec version.
const CloudEventSpecVersion = "1.0"

// CloudEventSource is the source of the CloudEvents produced by this service.
// This should be configured per service instance if multiple services might use this library.
// For now, it's specific to auth-service.
const CloudEventSource = "/auth-service"

// CloudEventDataContentType is the content type of the data attribute.
const CloudEventDataContentType = "application/json"

// CloudEvent represents a CloudEvents v1.0 compliant event structure.
type CloudEvent struct {
	SpecVersion     string          `json:"specversion"`
	ID              string          `json:"id"`
	Source          string          `json:"source"`
	Type            string          `json:"type"` // This will be models.EventType cast to string
	DataContentType string          `json:"datacontenttype,omitempty"`
	Subject         string          `json:"subject,omitempty"`
	Time            time.Time       `json:"time"`
	Data            json.RawMessage `json:"data,omitempty"` // Use json.RawMessage for delayed unmarshalling
}
