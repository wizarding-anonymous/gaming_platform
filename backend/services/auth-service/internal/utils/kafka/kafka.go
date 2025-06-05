// File: backend/services/auth-service/internal/utils/kafka/kafka.go
package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

// Producer представляет продюсера Kafka
type Producer struct {
	writer *kafka.Writer
	logger *zap.Logger
}

// NewProducer создает новый экземпляр Producer
func NewProducer(brokers []string, logger *zap.Logger) *Producer {
	writer := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Balancer:     &kafka.LeastBytes{},
		RequiredAcks: kafka.RequireAll,
		Async:        false,
	}

	return &Producer{
		writer: writer,
		logger: logger,
	}
}

// Close закрывает соединение с Kafka
func (p *Producer) Close() error {
	return p.writer.Close()
}

// Produce отправляет сообщение в Kafka
func (p *Producer) Produce(topic string, key string, value []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := p.writer.WriteMessages(ctx, kafka.Message{
		Topic: topic,
		Key:   []byte(key),
		Value: value,
		Time:  time.Now(),
	})

	if err != nil {
		p.logger.Error("Failed to write message to Kafka",
			zap.String("topic", topic),
			zap.String("key", key),
			zap.Error(err),
		)
		return fmt.Errorf("failed to write message to Kafka: %w", err)
	}

	return nil
}

// ProduceJSON отправляет JSON-сообщение в Kafka
func (p *Producer) ProduceJSON(topic string, key string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return p.Produce(topic, key, data)
}

// Consumer представляет консьюмера Kafka
type Consumer struct {
	reader *kafka.Reader
	logger *zap.Logger
}

// NewConsumer создает новый экземпляр Consumer
func NewConsumer(brokers []string, groupID, topic string, logger *zap.Logger) *Consumer {
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		GroupID:        groupID,
		Topic:          topic,
		MinBytes:       10e3,        // 10KB
		MaxBytes:       10e6,        // 10MB
		MaxWait:        1 * time.Second,
		StartOffset:    kafka.FirstOffset,
		CommitInterval: 1 * time.Second,
	})

	return &Consumer{
		reader: reader,
		logger: logger,
	}
}

// Close закрывает соединение с Kafka
func (c *Consumer) Close() error {
	return c.reader.Close()
}

// Consume читает сообщения из Kafka
func (c *Consumer) Consume(ctx context.Context, handler func(key, value []byte) error) error {
	for {
		msg, err := c.reader.ReadMessage(ctx)
		if err != nil {
			c.logger.Error("Failed to read message from Kafka", zap.Error(err))
			return fmt.Errorf("failed to read message from Kafka: %w", err)
		}

		c.logger.Debug("Received message from Kafka",
			zap.String("topic", msg.Topic),
			zap.String("key", string(msg.Key)),
			zap.Int("partition", msg.Partition),
			zap.Int64("offset", msg.Offset),
		)

		if err := handler(msg.Key, msg.Value); err != nil {
			c.logger.Error("Failed to handle message",
				zap.String("topic", msg.Topic),
				zap.String("key", string(msg.Key)),
				zap.Error(err),
			)
		}
	}
}

// ConsumeJSON читает JSON-сообщения из Kafka
func (c *Consumer) ConsumeJSON(ctx context.Context, handler func(key []byte, value interface{}) error, valueType interface{}) error {
	return c.Consume(ctx, func(key, value []byte) error {
		// Создание нового экземпляра типа значения
		valuePtr := valueType
		if err := json.Unmarshal(value, valuePtr); err != nil {
			return fmt.Errorf("failed to unmarshal JSON: %w", err)
		}

		return handler(key, valuePtr)
	})
}
