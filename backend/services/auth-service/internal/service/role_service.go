// File: backend/services/auth-service/internal/service/role_service.go

package service

import (
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	domainService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
	kafkaEvents "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/repository/interfaces"
	"go.uber.org/zap"
)

// RoleService предоставляет методы для работы с ролями
type RoleService struct {
	roleRepo         interfaces.RoleRepository
	userRepo         interfaces.UserRepository      // Still needed for validating user existence in some flows
	userRolesRepo    interfaces.UserRolesRepository // Added
	permissionRepo   interfaces.PermissionRepository
	kafkaClient      *kafkaEvents.Producer // Changed to Sarama-based producer
	cfg              *config.Config
	logger           *zap.Logger
	auditLogRecorder domainService.AuditLogRecorder // Added for audit logging
}

// NewRoleService создает новый экземпляр RoleService
func NewRoleService(
	roleRepo interfaces.RoleRepository,
	userRepo interfaces.UserRepository,
	userRolesRepo interfaces.UserRolesRepository, // Added
	permissionRepo interfaces.PermissionRepository,
	kafkaClient *kafkaEvents.Producer, // Changed to Sarama-based producer
	cfg *config.Config,
	logger *zap.Logger,
	auditLogRecorder domainService.AuditLogRecorder, // Added
) *RoleService {
	return &RoleService{
		roleRepo:         roleRepo,
		userRepo:         userRepo,
		userRolesRepo:    userRolesRepo, // Added
		permissionRepo:   permissionRepo,
		kafkaClient:      kafkaClient, // Assign Sarama-based producer
		cfg:              cfg,
		logger:           logger,
		auditLogRecorder: auditLogRecorder, // Added
	}
}
