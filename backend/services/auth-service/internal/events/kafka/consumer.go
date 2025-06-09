// File: backend/services/auth-service/internal/events/kafka/consumer.go
package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Shopify/sarama"
	"github.com/google/uuid"
	"go.uber.org/zap"
	// Assuming a common logger, replace if different
	"github.com/your-org/auth-service/internal/utils/logger"
)

// CloudEvent defines the structure for CloudEvents v1.0.
// Note: This definition should ideally be shared, e.g., in an internal/events/models package.
// Duplicating it here for now as per the subtask structure.
type CloudEvent struct {
	SpecVersion     string          `json:"specversion"`
	Type            string          `json:"type"`
	Source          string          `json:"source"`
	Subject         *string         `json:"subject,omitempty"`
	ID              string          `json:"id"`
	Time            time.Time       `json:"time"`
	DataContentType *string         `json:"datacontenttype,omitempty"`
	Data            json.RawMessage `json:"data,omitempty"` // Use json.RawMessage for Data
	// Extensions can be added here as map[string]interface{} `json:"..."`
}

// EventHandler defines the function signature for handling a deserialized CloudEvent.
type EventHandler func(ctx context.Context, event CloudEvent) error

// ConsumerGroup manages a Sarama consumer group and routes messages to registered handlers.
type ConsumerGroup struct {
	consumerGroup sarama.ConsumerGroup
	logger        logger.Logger // Using the imported logger.Logger
	handlers      map[string]EventHandler
	topics        []string
	groupID       string
	ready         chan bool // Signals that the consumer group is ready
	wg            sync.WaitGroup
	cancelCtx     context.CancelFunc // To signal shutdown
}

// NewConsumerGroupConfig holds configuration for creating a new ConsumerGroup.
type NewConsumerGroupConfig struct {
	Brokers       []string
	Topics        []string
	GroupID       string
	SaramaConfig  *sarama.Config // Allow passing a custom Sarama config
	Logger        logger.Logger
	InitialOffset int64 // sarama.OffsetOldest or sarama.OffsetNewest
}

// NewConsumerGroup creates a new Kafka consumer group.
func NewConsumerGroup(cfg NewConsumerGroupConfig) (*ConsumerGroup, error) {
	if cfg.Logger == nil {
		// Fallback to a default zap logger if none provided (replace with actual default)
		zapLogger, _ := zap.NewProduction()
		cfg.Logger = logger.NewZapLogger(zapLogger) // Assuming NewZapLogger exists
	}

	if cfg.SaramaConfig == nil {
		saramaCfg := sarama.NewConfig()
		saramaCfg.Version = sarama.V2_8_0_0 // Or your Kafka version
		saramaCfg.Consumer.Group.Rebalance.Strategy = sarama.BalanceStrategyRange
		saramaCfg.Consumer.Offsets.Initial = cfg.InitialOffset
		if cfg.InitialOffset == 0 {
			saramaCfg.Consumer.Offsets.Initial = sarama.OffsetOldest // Default to oldest
		}
		cfg.SaramaConfig = saramaCfg
	}

	consumerGroup, err := sarama.NewConsumerGroup(cfg.Brokers, cfg.GroupID, cfg.SaramaConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create consumer group: %w", err)
	}

	cg := &ConsumerGroup{
		consumerGroup: consumerGroup,
		logger:        cfg.Logger.Named("kafka_consumer_group"),
		handlers:      make(map[string]EventHandler),
		topics:        cfg.Topics,
		groupID:       cfg.GroupID,
		ready:         make(chan bool),
	}

	return cg, nil
}

// RegisterHandler registers an event handler for a specific event type.
func (cg *ConsumerGroup) RegisterHandler(eventType string, handler EventHandler) {
	cg.logger.Info("Registering handler", "eventType", eventType)
	cg.handlers[eventType] = handler
}

// StartConsuming starts the consumer group and blocks until the context is canceled.
func (cg *ConsumerGroup) StartConsuming(ctx context.Context) {
	ctx, cg.cancelCtx = context.WithCancel(ctx) // Store cancel func to stop consumer

	cg.wg.Add(1)
	go func() {
		defer cg.wg.Done()
		cg.logger.Info("Consumer group started", "topics", cg.topics, "groupID", cg.groupID)
		for {
			// `Consume` should be called inside an infinite loop, when a
			// server-side rebalance happens, the consumer session will need to be
			// recreated to get essentially a new stream.
			if err := cg.consumerGroup.Consume(ctx, cg.topics, cg); err != nil {
				if errors.Is(err, sarama.ErrClosedConsumerGroup) {
					cg.logger.Info("Consumer group closed gracefully.")
					return
				}
				cg.logger.Error("Error from consumer", "error", err)
				// Potentially exit or retry after a delay
				if ctx.Err() != nil { // Context cancelled
					return
				}
				time.Sleep(1 * time.Second) // Avoid tight loop on persistent errors
			}
			// Check if context was cancelled, signaling that the consumer should stop
			if ctx.Err() != nil {
				cg.logger.Info("Consumer group context cancelled.")
				return
			}
			cg.ready = make(chan bool) // Recreate ready channel for next session
		}
	}()

	<-cg.ready // Wait until the consumer has been set up
	cg.logger.Info("Consumer group up and running!")
}

// Close stops the consumer group and waits for all processing to complete.
func (cg *ConsumerGroup) Close() error {
	cg.logger.Info("Closing consumer group...")
	if cg.cancelCtx != nil {
		cg.cancelCtx() // Signal consumer loop to stop
	}

	// Wait for the consumer goroutine to finish
	// Add a timeout to prevent indefinite blocking if wg.Done() is never called.
	waitTimeout := 10 * time.Second
	done := make(chan struct{})
	go func() {
		cg.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		cg.logger.Info("Consumer group goroutine finished.")
	case <-time.After(waitTimeout):
		cg.logger.Warn("Timeout waiting for consumer group goroutine to finish.")
	}

	if err := cg.consumerGroup.Close(); err != nil {
		return fmt.Errorf("failed to close consumer group: %w", err)
	}
	cg.logger.Info("Consumer group closed successfully.")
	return nil
}

// Setup is run at the beginning of a new session, before ConsumeClaim.
func (cg *ConsumerGroup) Setup(session sarama.ConsumerGroupSession) error {
	cg.logger.Info("Consumer group setup", "memberID", session.MemberID(), "claims", session.Claims())
	close(cg.ready) // Signal that the consumer is ready
	return nil
}

// Cleanup is run at the end of a session, once all ConsumeClaim goroutines have exited.
func (cg *ConsumerGroup) Cleanup(session sarama.ConsumerGroupSession) error {
	cg.logger.Info("Consumer group cleanup", "memberID", session.MemberID())
	return nil
}

// ConsumeClaim must start a consumer loop of ConsumerGroupClaim's Messages().
func (cg *ConsumerGroup) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	// NOTE:
	// Do not move the code below to a goroutine.
	// The `ConsumeClaim` method must block until the claim is closed, either due
	// to a rebalance or because the session is marked for closing.
	for message := range claim.Messages() {
		cg.logger.Debug("Message claimed", "value_len", len(message.Value), "topic", message.Topic, "partition", message.Partition, "offset", message.Offset)

		var cloudEvent CloudEvent
		if err := json.Unmarshal(message.Value, &cloudEvent); err != nil {
			cg.logger.Error("Failed to unmarshal message into CloudEvent", "error", err, "raw_message", string(message.Value))
			session.MarkMessage(message, "") // Mark as processed even if unmarshal fails to avoid blocking
			continue
		}

		// Context enrichment (basic example)
		ctx := session.Context() // Get context from the session
		// If TraceID is expected in CloudEvent extensions:
		// if traceIDVal, ok := cloudEvent.Extensions["traceid"]; ok {
		//    if traceIDStr, ok := traceIDVal.(string); ok {
		//        ctx = context.WithValue(ctx, "traceID", traceIDStr)
		//    }
		// }
		if cloudEvent.Subject != nil {
			ctx = context.WithValue(ctx, "userID", *cloudEvent.Subject)
		}
		ctx = context.WithValue(ctx, "eventID", cloudEvent.ID)
		ctx = context.WithValue(ctx, "eventType", cloudEvent.Type)


		handler, ok := cg.handlers[cloudEvent.Type]
		if !ok {
			cg.logger.Warn("No handler registered for event type", "eventType", cloudEvent.Type)
			session.MarkMessage(message, "") // Mark as processed
			continue
		}

		err := handler(ctx, cloudEvent)
		if err != nil {
			cg.logger.Error("Error processing event", "eventType", cloudEvent.Type, "eventID", cloudEvent.ID, "error", err)
			// Decide on retry/dead-letter queue strategy here. For now, just marking as processed.
		}
		session.MarkMessage(message, "") // Mark message as processed
	}
	return nil
}
