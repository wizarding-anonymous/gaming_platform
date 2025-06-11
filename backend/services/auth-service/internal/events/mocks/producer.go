package mocks

import (
	"context"

	"github.com/stretchr/testify/mock"

	kafka "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka"
)

type MockProducer struct {
	mock.Mock
}

func (m *MockProducer) PublishCloudEvent(ctx context.Context, topic string, eventType kafka.EventType, subject *string, dataContentType *string, dataPayload interface{}) error {
	args := m.Called(ctx, topic, eventType, subject, dataContentType, dataPayload)
	return args.Error(0)
}

func (m *MockProducer) PublishAccountLinkedEvent(ctx context.Context, event kafka.AccountLinkedEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func (m *MockProducer) PublishUserRegisteredEvent(ctx context.Context, event kafka.UserRegisteredEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func (m *MockProducer) PublishUserLoggedInEvent(ctx context.Context, event kafka.UserLoggedInEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func (m *MockProducer) Close() error {
	args := m.Called()
	return args.Error(0)
}
