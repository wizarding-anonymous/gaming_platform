// File: backend/services/account-service/internal/infrastructure/kafka/producer_test.go
package kafka

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKafkaEventProducer(t *testing.T) {
	brokers := []string{"localhost:9092"}
	source := "test-service"

	p := NewKafkaEventProducer(brokers, source)

	require.NotNil(t, p)
	assert.Equal(t, source, p.sourceName)
	require.NotNil(t, p.writer)
}
