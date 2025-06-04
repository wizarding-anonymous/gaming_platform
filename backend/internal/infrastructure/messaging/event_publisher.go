package messaging

import (
	"context"
)

// EventPublisher defines the interface for publishing domain events.
type EventPublisher interface {
	// Publish sends an event to a message broker (e.g., Kafka).
	// eventData: The actual payload of the event (a Go struct or map).
	// key: The Kafka message key, often a userID or entityID for partitioning.
	// eventType: The CloudEvents "type" attribute (e.g., "auth.user.registered").
	// subject: The CloudEvents "subject" attribute (e.g., the userID or entityID).
	// topic: The Kafka topic to publish to. If empty, a default topic might be used.
	Publish(
		ctx context.Context,
		eventData interface{},
		key string,
		eventType string,
		subject string,
		topic string, // Can be made optional if a default topic is configured in the publisher
	) error

	// Close cleans up any resources used by the publisher (e.g., Kafka producer).
	Close()
}

// CloudEvent represents the structure of a CloudEvents v1.0 compliant message.
// This is a simplified version; official SDKs provide more comprehensive structs.
type CloudEvent struct {
	ID              string      `json:"id"`
	Source          string      `json:"source"` // e.g., "auth-service"
	SpecVersion     string      `json:"specversion"`
	Type            string      `json:"type"` // e.g., "auth.user.registered"
	Subject         string      `json:"subject,omitempty"`
	DataContentType string      `json:"datacontenttype,omitempty"` // e.g., "application/json"
	Time            string      `json:"time,omitempty"`            // ISO 8601
	Data            interface{} `json:"data,omitempty"`            // The actual event payload
}
