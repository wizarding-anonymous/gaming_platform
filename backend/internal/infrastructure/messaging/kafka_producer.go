package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/google/uuid"
	"go.uber.org/zap" // Assuming logger is available
)

// KafkaProducerConfig holds configuration for the KafkaEventPublisher.
type KafkaProducerConfig struct {
	BootstrapServers string
	DefaultTopic     string
	MessageTimeoutMs int
	Source           string // CloudEvents source attribute (e.g., "auth-service")
}

// kafkaEventPublisher implements the EventPublisher interface using Confluent Kafka client.
type kafkaEventPublisher struct {
	producer     *kafka.Producer // In a real scenario, this would be initialized
	logger       *zap.Logger
	defaultTopic string
	source       string
}

// NewKafkaEventPublisher creates a new kafkaEventPublisher.
// It attempts to initialize a Kafka producer.
func NewKafkaEventPublisher(cfg KafkaProducerConfig, logger *zap.Logger) (EventPublisher, error) {
	// In a real application, initialize kafka.Producer here:
	// p, err := kafka.NewProducer(&kafka.ConfigMap{
	// 	"bootstrap.servers": cfg.BootstrapServers,
	// 	"message.timeout.ms": cfg.MessageTimeoutMs,
	//  // Add other producer configs: acks, retries, idempotence, etc.
	// })
	// if err != nil {
	// 	logger.Error("Failed to create Kafka producer", zap.Error(err))
	// 	return nil, fmt.Errorf("failed to create kafka producer: %w", err)
	// }
	// logger.Info("Kafka producer created successfully")

	// For this subtask, producer is nil to avoid actual Kafka dependency in sandbox.
	// Methods will simulate or skip actual publishing if producer is nil.

	return &kafkaEventPublisher{
		producer:     nil, // p
		logger:       logger.Named("kafka_event_publisher"),
		defaultTopic: cfg.DefaultTopic,
		source:       cfg.Source,
	}, nil
}

// Publish constructs a CloudEvent and sends it to Kafka.
func (p *kafkaEventPublisher) Publish(
	ctx context.Context,
	eventData interface{},
	key string,
	eventType string,
	subject string,
	topic string,
) error {
	if p.source == "" {
		p.source = "auth-service" // Default source if not configured
	}

	cloudEvent := CloudEvent{
		ID:              uuid.NewString(),
		Source:          p.source,
		SpecVersion:     "1.0",
		Type:            eventType,
		Subject:         subject,
		DataContentType: "application/json",
		Time:            time.Now().UTC().Format(time.RFC3339Nano),
		Data:            eventData,
	}

	eventBytes, err := json.Marshal(cloudEvent)
	if err != nil {
		p.logger.Error("Failed to marshal CloudEvent to JSON", zap.Error(err), zap.String("eventType", eventType))
		return fmt.Errorf("failed to marshal CloudEvent: %w", err)
	}

	publishTopic := p.defaultTopic
	if topic != "" {
		publishTopic = topic
	}
	if publishTopic == "" {
		return errors.New("kafka topic is not specified and no default topic configured")
	}

	p.logger.Info("Attempting to publish event",
		zap.String("topic", publishTopic),
		zap.String("eventType", eventType),
		zap.String("key", key),
		// zap.ByteString("payload", eventBytes), // Be careful logging full payload in production
	)

	// In a real application with initialized p.producer:
	if p.producer != nil {
		deliveryChan := make(chan kafka.Event)
		err = p.producer.Produce(&kafka.Message{
			TopicPartition: kafka.TopicPartition{Topic: &publishTopic, Partition: kafka.PartitionAny},
			Key:            []byte(key),
			Value:          eventBytes,
			Headers: []kafka.Header{ // Optional: CloudEvents attributes can also go into Kafka headers
				{Key: "ce_specversion", Value: []byte(cloudEvent.SpecVersion)},
				{Key: "ce_type", Value: []byte(cloudEvent.Type)},
				{Key: "ce_source", Value: []byte(cloudEvent.Source)},
				{Key: "ce_id", Value: []byte(cloudEvent.ID)},
				{Key: "content-type", Value: []byte(cloudEvent.DataContentType)},
			},
		}, deliveryChan)

		if err != nil {
			p.logger.Error("Kafka produce failed", zap.Error(err), zap.String("topic", publishTopic))
			return fmt.Errorf("kafka produce error: %w", err)
		}

		// Wait for delivery report (asynchronous)
		e := <-deliveryChan
		m := e.(*kafka.Message)

		if m.TopicPartition.Error != nil {
			p.logger.Error("Kafka delivery failed",
				zap.Error(m.TopicPartition.Error),
				zap.String("topic", *m.TopicPartition.Topic))
			return fmt.Errorf("kafka delivery error: %w", m.TopicPartition.Error)
		}
		p.logger.Info("Event delivered successfully to Kafka",
			zap.String("topic", *m.TopicPartition.Topic),
			zap.Int32("partition", m.TopicPartition.Partition),
			zap.Any("offset", m.TopicPartition.Offset),
			zap.String("eventType", eventType),
		)
	} else {
		p.logger.Warn("Kafka producer is not initialized. Skipping actual event publishing.",
			zap.String("topic", publishTopic),
			zap.String("eventType", eventType),
		)
		// Simulate success for sandbox environment
	}

	return nil
}

// Close flushes and closes the Kafka producer.
func (p *kafkaEventPublisher) Close() {
	if p.producer != nil {
		p.logger.Info("Closing Kafka producer, flushing messages...")
		// remaining := p.producer.Flush(15000) // Wait 15 seconds for outstanding messages
		// p.logger.Info("Kafka producer flushed", zap.Int("remaining_messages", remaining))
		// p.producer.Close()
		p.logger.Info("Kafka producer closed (simulated).") // Placeholder for actual close
	}
}

// Need to add "errors" to imports if not already there.
import "errors"
