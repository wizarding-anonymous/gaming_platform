// File: backend/services/auth-service/internal/events/kafka/producer.go

package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Shopify/sarama"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
	// "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/models" // For CloudEvent and EventType constants
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/logger" // Assuming logger interface is here
)

// CloudEvent defines the structure for CloudEvents v1.0.
type CloudEvent struct {
	SpecVersion     string                 `json:"specversion"`
	Type            string                 `json:"type"`
	Source          string                 `json:"source"`
	Subject         *string                `json:"subject,omitempty"`
	ID              string                 `json:"id"`
	Time            time.Time              `json:"time"`
	DataContentType *string                `json:"datacontenttype,omitempty"`
	Data            interface{}            `json:"data,omitempty"`
	Extensions      map[string]interface{} `json:"extensions,omitempty"`
}

// EventType is a string alias for event types.
type EventType string

// Constants for CloudEvent fields
const (
	CloudEventSpecVersion     = "1.0"
	CloudEventDataContentType = "application/json"
)

// Producer представляет собой продюсер Kafka для отправки событий CloudEvents
type Producer struct {
	producer sarama.SyncProducer
	logger   logger.Logger // Using the imported logger.Logger interface
	source   string        // Default source for CloudEvents from this producer
}

// NewProducer создает новый экземпляр продюсера Kafka.
// cloudEventSource should be a URN or path identifying the service, e.g., "/auth-service".
func NewProducer(brokers []string, logger logger.Logger, cloudEventSource string) (*Producer, error) {
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 5
	config.Producer.Return.Successes = true
	config.Producer.Compression = sarama.CompressionSnappy // Or sarama.CompressionZSTD, etc.
	config.Producer.Flush.Frequency = 500 * time.Millisecond
	config.Producer.Idempotent = true // Requires Kafka >= 0.11 & broker-side settings
	config.Net.MaxOpenRequests = 1    // For idempotent producer, limit inflight messages

	producer, err := sarama.NewSyncProducer(brokers, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kafka producer: %w", err)
	}

	return &Producer{
		producer: producer,
		logger:   logger,
		source:   cloudEventSource,
	}, nil
}

// PublishCloudEvent constructs a CloudEvent and sends it to the specified Kafka topic.
// - topic: The Kafka topic to publish to.
// - eventType: The CloudEvents type string (e.g., "com.example.user.created").
// - subject: An optional subject for the CloudEvent (e.g., user ID, entity ID). Can be empty.
// - dataContentType: The content type of the data payload (e.g., "application/json").
// - dataPayload: The actual event data struct.
func (p *Producer) PublishCloudEvent(ctx context.Context, topic string, eventType EventType, subject *string, dataContentType *string, dataPayload interface{}) error {
	eventID, err := uuid.NewRandom()
	if err != nil {
		p.logger.Error("Failed to generate CloudEvent ID", "error", err)
		return fmt.Errorf("failed to generate CloudEvent ID: %w", err)
	}

	spanCtx := trace.SpanContextFromContext(ctx)
	var traceID string
	if spanCtx.IsValid() {
		traceID = spanCtx.TraceID().String()
	}

	actualDataContentType := CloudEventDataContentType // Default
	if dataContentType != nil && *dataContentType != "" {
		actualDataContentType = *dataContentType
	}

	cloudEvent := CloudEvent{
		SpecVersion:     CloudEventSpecVersion,
		ID:              eventID.String(),
		Source:          p.source, // Use configured source from NewProducer
		Type:            string(eventType),
		DataContentType: &actualDataContentType,
		Subject:         subject,
		Time:            time.Now().UTC(),
		Data:            dataPayload,
	}

	if traceID != "" {
		cloudEvent.Extensions = map[string]interface{}{"trace_id": traceID}
	}

	eventJSON, err := json.Marshal(cloudEvent)
	if err != nil {
		p.logger.Error("Failed to marshal CloudEvent to JSON", "error", err, "eventType", string(eventType), "eventID", cloudEvent.ID)
		return fmt.Errorf("failed to marshal CloudEvent to JSON: %w", err)
	}

	var messageKey sarama.Encoder
	if subject != nil && *subject != "" { // Use subject for partitioning if available and meaningful
		messageKey = sarama.StringEncoder(*subject)
	}
	// If no subject, Sarama will use random partitioning unless a key is set.
	// Alternatively, could use eventID.String() for key if specific partitioning not needed based on subject.

	msg := &sarama.ProducerMessage{
		Topic: topic,
		Value: sarama.ByteEncoder(eventJSON),
		Key:   messageKey,
		// Headers: []sarama.RecordHeader{{Key: []byte("traceparent"), Value: []byte(traceID)}}, // Example for tracing
	}

	partition, offset, err := p.producer.SendMessage(msg)
	if err != nil {
		p.logger.Error("Failed to send CloudEvent to Kafka",
			"error", err,
			"topic", topic,
			"eventType", string(eventType),
			"eventID", cloudEvent.ID,
			"subject", subject,
		)
		return fmt.Errorf("failed to send CloudEvent to Kafka: %w", err)
	}

	p.logger.Info("CloudEvent sent to Kafka",
		"topic", topic,
		"eventType", string(eventType),
		"eventID", cloudEvent.ID,
		"subject", subject,
		"partition", partition,
		"offset", offset,
	)

	return nil
}

// Close закрывает продюсера Kafka
func (p *Producer) Close() error {
	if err := p.producer.Close(); err != nil {
		p.logger.Error("Failed to close Kafka producer", "error", err)
		return fmt.Errorf("failed to close Kafka producer: %w", err)
	}
	p.logger.Info("Kafka producer closed successfully")
	return nil
}
