// File: internal/events/kafka/producer.go

package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Shopify/sarama"
	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/events/models" // For CloudEvent and EventType constants
	"github.com/your-org/auth-service/internal/utils/logger"  // Assuming logger interface is here
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
	config.Producer.Idempotent = true    // Requires Kafka >= 0.11 & broker-side settings
	config.Net.MaxOpenRequests = 1     // For idempotent producer, limit inflight messages

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
// - eventType: The CloudEvents type string (e.g., models.AuthUserRegisteredV1).
// - subject: An optional subject for the CloudEvent (e.g., user ID, entity ID). Can be empty.
// - dataPayload: The actual event data struct (e.g., models.UserRegisteredPayload).
func (p *Producer) PublishCloudEvent(ctx context.Context, topic string, eventType models.EventType, subject string, dataPayload interface{}) error {
	eventID, err := uuid.NewRandom()
	if err != nil {
		p.logger.Error("Failed to generate CloudEvent ID", "error", err)
		return fmt.Errorf("failed to generate CloudEvent ID: %w", err)
	}

	// TODO: Extract traceID from context if available and add as an extension attribute or in header.
	// traceID, _ := ctx.Value("traceID").(string)

	cloudEvent := models.CloudEvent{
		SpecVersion:     models.CloudEventSpecVersion,
		ID:              eventID.String(),
		Source:          p.source, // Use configured source from NewProducer
		Type:            string(eventType),
		DataContentType: models.CloudEventDataContentType,
		Subject:         subject,
		Time:            time.Now().UTC(),
		Data:            dataPayload,
	}

	eventJSON, err := json.Marshal(cloudEvent)
	if err != nil {
		p.logger.Error("Failed to marshal CloudEvent to JSON", "error", err, "eventType", eventType, "eventID", cloudEvent.ID)
		return fmt.Errorf("failed to marshal CloudEvent to JSON: %w", err)
	}

	var messageKey sarama.Encoder
	if subject != "" { // Use subject for partitioning if available and meaningful
		messageKey = sarama.StringEncoder(subject)
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
			"eventType", eventType,
			"eventID", cloudEvent.ID,
			"subject", subject,
		)
		return fmt.Errorf("failed to send CloudEvent to Kafka: %w", err)
	}

	p.logger.Info("CloudEvent sent to Kafka",
		"topic", topic,
		"eventType", eventType,
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
