// File: backend/services/account-service/internal/app/usecase/account_usecase.go
// account-service/internal/app/usecase/account_usecase.go
package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/entity"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/repository"
)

// AccountUseCase описывает бизнес‑логику работы с аккаунтами.
type AccountUseCase interface {
	// Создание / чтение / обновление / удаление
	CreateAccount(ctx context.Context, username, email, password, role string) (*entity.Account, error)
	GetAccountByID(ctx context.Context, id uuid.UUID) (*entity.Account, error)
	GetAccountByUsername(ctx context.Context, username string) (*entity.Account, error)
	GetAccountByEmail(ctx context.Context, email string) (*entity.Account, error)
	UpdateAccount(ctx context.Context, account *entity.Account) error
	DeleteAccount(ctx context.Context, id uuid.UUID) error          // soft‑delete
	HardDeleteAccount(ctx context.Context, id uuid.UUID) error      // hard‑delete
	ListAccounts(ctx context.Context, filter repository.AccountFilter) ([]*entity.Account, int64, error)

	// Управление статусом
	ActivateAccount(ctx context.Context, id uuid.UUID) error
	SuspendAccount(ctx context.Context, id uuid.UUID, reason string) error
	BanAccount(ctx context.Context, id uuid.UUID, reason string, until *time.Time) error

	// Обновление атрибутов
	UpdateRole(ctx context.Context, id uuid.UUID, role string) error
	UpdateEmail(ctx context.Context, id uuid.UUID, email string) error
	UpdateUsername(ctx context.Context, id uuid.UUID, username string) error

	// Пароли
	ChangePassword(ctx context.Context, id uuid.UUID, oldPassword, newPassword string) error
	ResetPassword(ctx context.Context, id uuid.UUID, token, newPassword string) error
	RequestPasswordReset(ctx context.Context, email string) error

	// Верификация e‑mail
	VerifyEmail(ctx context.Context, id uuid.UUID, code string) error
	SendVerificationEmail(ctx context.Context, id uuid.UUID) error

	// Поиск
	SearchAccounts(ctx context.Context, query string, limit, offset int) ([]*entity.Account, int64, error)
}

// AccountUseCaseImpl — реализация бизнес‑логики.
type AccountUseCaseImpl struct {
	accountRepo     repository.AccountRepository
	authMethodRepo  repository.AuthMethodRepository
	profileRepo     repository.ProfileRepository
	contactInfoRepo repository.ContactInfoRepository
	settingRepo     repository.SettingRepository
	avatarRepo      repository.AvatarRepository

	authClient     AuthServiceClient
	notifyClient   NotificationServiceClient
	eventPublisher EventPublisher
	passwordHasher PasswordHasher
	tokenGenerator TokenGenerator
	s3Client       S3Client
}

// NewAccountUseCase создает экземпляр реализации.
func NewAccountUseCase(
	accountRepo repository.AccountRepository,
	authMethodRepo repository.AuthMethodRepository,
	profileRepo repository.ProfileRepository,
	contactInfoRepo repository.ContactInfoRepository,
	settingRepo repository.SettingRepository,
	avatarRepo repository.AvatarRepository,
	authClient AuthServiceClient,
	notifyClient NotificationServiceClient,
	eventPublisher EventPublisher,
	passwordHasher PasswordHasher,
	tokenGenerator TokenGenerator,
	s3Client S3Client,
) *AccountUseCaseImpl {
	return &AccountUseCaseImpl{
		accountRepo:     accountRepo,
		authMethodRepo:  authMethodRepo,
		profileRepo:     profileRepo,
		contactInfoRepo: contactInfoRepo,
		settingRepo:     settingRepo,
		avatarRepo:      avatarRepo,
		authClient:      authClient,
		notifyClient:    notifyClient,
		eventPublisher:  eventPublisher,
		passwordHasher:  passwordHasher,
		tokenGenerator:  tokenGenerator,
		s3Client:        s3Client,
	}
}

/* ---------- Создание и общий CRUD ---------- */

// CreateAccount создает новый аккаунт.
func (uc *AccountUseCaseImpl) CreateAccount(ctx context.Context, username, email, password, role string) (*entity.Account, error) {
	// Проверка уникальности username / email
	if exists, err := uc.accountRepo.ExistsByUsername(ctx, username); err != nil {
		return nil, err
	} else if exists {
		return nil, errors.New("username already exists")
	}

	if exists, err := uc.accountRepo.ExistsByEmail(ctx, email); err != nil {
		return nil, err
	} else if exists {
		return nil, errors.New("email already exists")
	}

	// Создание аккаунта
	account := entity.NewAccount(username, email, role)
	if err := uc.accountRepo.Create(ctx, account); err != nil {
		return nil, err
	}

	// Парольный метод аутентификации
	hashed, err := uc.passwordHasher.HashPassword(password)
	if err != nil {
		return nil, err
	}
	if err := uc.authMethodRepo.Create(ctx, entity.NewPasswordAuthMethod(account.ID, email, hashed)); err != nil {
		return nil, err
	}

	// Профиль
	if err := uc.profileRepo.Create(ctx, entity.NewProfile(account.ID, username)); err != nil {
		return nil, err
	}

	// Контактная информация
	ci := entity.NewContactInfo(account.ID, entity.ContactTypeEmail, email, entity.ContactVisibilityPrivate)
	ci.SetPrimary(true)
	if err := uc.contactInfoRepo.Create(ctx, ci); err != nil {
		return nil, err
	}

	// Настройки по умолчанию
	for _, cat := range []entity.SettingCategory{
		entity.SettingCategoryPrivacy,
		entity.SettingCategoryNotification,
		entity.SettingCategoryInterface,
		entity.SettingCategorySecurity,
	} {
		if err := uc.settingRepo.Create(ctx, entity.NewSetting(account.ID, cat)); err != nil {
			return nil, err
		}
	}

	// Событие + письмо для верификации
	_ = uc.eventPublisher.PublishAccountCreated(ctx, account)
	_ = uc.SendVerificationEmail(ctx, account.ID)

	return account, nil
}

func (uc *AccountUseCaseImpl) GetAccountByID(ctx context.Context, id uuid.UUID) (*entity.Account, error) {
	return uc.accountRepo.GetByID(ctx, id)
}
func (uc *AccountUseCaseImpl) GetAccountByUsername(ctx context.Context, username string) (*entity.Account, error) {
	return uc.accountRepo.GetByUsername(ctx, username)
}
func (uc *AccountUseCaseImpl) GetAccountByEmail(ctx context.Context, email string) (*entity.Account, error) {
	return uc.accountRepo.GetByEmail(ctx, email)
}

func (uc *AccountUseCaseImpl) UpdateAccount(ctx context.Context, account *entity.Account) error {
	ok, err := uc.accountRepo.Exists(ctx, account.ID)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("account not found")
	}
	if err := uc.accountRepo.Update(ctx, account); err != nil {
		return err
	}
	_ = uc.eventPublisher.PublishAccountUpdated(ctx, account)
	return nil
}

/* ---------- Удаление ---------- */

// DeleteAccount выполняет soft‑delete и анонимизацию.
func (uc *AccountUseCaseImpl) DeleteAccount(ctx context.Context, id uuid.UUID) error {
	account, err := uc.accountRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Анонимизация и каскадное удаление вспомогательных данных
	if err := uc.accountRepo.Anonymize(ctx, id); err != nil {
		return err
	}
	if profile, err := uc.profileRepo.GetByAccountID(ctx, id); err != nil {
		return err
	} else if profile != nil {
		if err := uc.profileRepo.Anonymize(ctx, profile.ID); err != nil {
			return err
		}
	}
	if err := uc.contactInfoRepo.DeleteByAccountID(ctx, id); err != nil {
		return err
	}
	if err := uc.authMethodRepo.DeleteByAccountID(ctx, id); err != nil {
		return err
	}
	if err := uc.settingRepo.DeleteByAccountID(ctx, id); err != nil {
		return err
	}

	// Аватары
	if avatars, err := uc.avatarRepo.GetByAccountID(ctx, id); err == nil {
		for _, a := range avatars {
			_ = uc.s3Client.DeleteObject(ctx, a.Filename)
			if err := uc.avatarRepo.Delete(ctx, a.ID); err != nil {
				return err
			}
		}
	}

	// Soft‑delete
	if err := uc.accountRepo.Delete(ctx, id); err != nil {
		return err
	}

	_ = uc.eventPublisher.PublishAccountDeleted(ctx, account)
	return nil
}

// HardDeleteAccount удаляет аккаунт физически.
func (uc *AccountUseCaseImpl) HardDeleteAccount(ctx context.Context, id uuid.UUID) error {
	account, err := uc.accountRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Удаляем дочерние данные
	for _, step := range []func(context.Context, uuid.UUID) error{
		uc.profileRepo.DeleteByAccountID,
		uc.contactInfoRepo.DeleteByAccountID,
		uc.authMethodRepo.DeleteByAccountID,
		uc.settingRepo.DeleteByAccountID,
	} {
		if err := step(ctx, id); err != nil {
			return err
		}
	}

	if avatars, err := uc.avatarRepo.GetByAccountID(ctx, id); err == nil {
		for _, a := range avatars {
			_ = uc.s3Client.DeleteObject(ctx, a.Filename)
			if err := uc.avatarRepo.Delete(ctx, a.ID); err != nil {
				return err
			}
		}
	}

	if err := uc.accountRepo.HardDelete(ctx, id); err != nil {
		return err
	}

	_ = uc.eventPublisher.PublishAccountHardDeleted(ctx, account)
	return nil
}

/* ---------- Чтение списков ---------- */

func (uc *AccountUseCaseImpl) ListAccounts(ctx context.Context, filter repository.AccountFilter) ([]*entity.Account, int64, error) {
	return uc.accountRepo.List(ctx, filter)
}

/* ---------- Управление статусом ---------- */

func (uc *AccountUseCaseImpl) ActivateAccount(ctx context.Context, id uuid.UUID) error {
	acc, err := uc.accountRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	acc.Activate()
	if err := uc.accountRepo.Update(ctx, acc); err != nil {
		return err
	}
	_ = uc.eventPublisher.PublishAccountStatusChanged(ctx, acc)
	return nil
}

func (uc *AccountUseCaseImpl) SuspendAccount(ctx context.Context, id uuid.UUID, reason string) error {
	acc, err := uc.accountRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	acc.Suspend(reason)
	if err := uc.accountRepo.Update(ctx, acc); err != nil {
		return err
	}
	_ = uc.eventPublisher.PublishAccountStatusChanged(ctx, acc)
	_ = uc.notifyClient.SendAccountSuspendedNotification(ctx, acc.ID, reason)
	return nil
}

func (uc *AccountUseCaseImpl) BanAccount(ctx context.Context, id uuid.UUID, reason string, until *time.Time) error {
	acc, err := uc.accountRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	acc.Ban(reason, until)
	if err := uc.accountRepo.Update(ctx, acc); err != nil {
		return err
	}
	_ = uc.eventPublisher.PublishAccountStatusChanged(ctx, acc)
	_ = uc.notifyClient.SendAccountBannedNotification(ctx, acc.ID, reason, until)
	return nil
}

/* ---------- Обновление атрибутов ---------- */

func (uc *AccountUseCaseImpl) UpdateRole(ctx context.Context, id uuid.UUID, role string) error {
	acc, err := uc.accountRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}
	acc.UpdateRole(role)
	if err := uc.accountRepo.Update(ctx, acc); err != nil {
		return err
	}
	_ = uc.eventPublisher.PublishAccountRoleChanged(ctx, acc)
	return nil
}

func (uc *AccountUseCaseImpl) UpdateEmail(ctx context.Context, id uuid.UUID, email string) error {
	// Проверка уникальности
	if ok, err := uc.accountRepo.ExistsByEmail(ctx, email); err != nil {
		return err
	} else if ok {
		return errors.New("email already exists")
	}

	acc, err := uc.accountRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	oldEmail := acc.Email
	acc.UpdateEmail(email)
	if err := uc.accountRepo.Update(ctx, acc); err != nil {
		return err
	}

	// Обновляем контактную информацию
	if contacts, err := uc.contactInfoRepo.GetByAccountIDAndType(ctx, id, entity.ContactTypeEmail); err == nil {
		for _, c := range contacts {
			if c.Value == oldEmail {
				c.UpdateValue(email)
				_ = uc.contactInfoRepo.Update(ctx, c)
				break
			}
		}
	}

	// Обновляем методы аутентификации
	if ams, err := uc.authMethodRepo.GetByAccountID(ctx, id); err == nil {
		for _, am := range ams {
			if am.Type == entity.AuthMethodTypePassword && am.Identifier == oldEmail {
				am.Identifier = email
				_ = uc.authMethodRepo.Update(ctx, am)
				break
			}
		}
	}

	_ = uc.eventPublisher.PublishAccountEmailChanged(ctx, acc, oldEmail)
	_ = uc.SendVerificationEmail(ctx, acc.ID)
	return nil
}

func (uc *AccountUseCaseImpl) UpdateUsername(ctx context.Context, id uuid.UUID, username string) error {
	if ok, err := uc.accountRepo.ExistsByUsername(ctx, username); err != nil {
		return err
	} else if ok {
		return errors.New("username already exists")
	}

	acc, err := uc.accountRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	old := acc.Username
	acc.UpdateUsername(username)
	if err := uc.accountRepo.Update(ctx, acc); err != nil {
		return err
	}

	if profile, err := uc.profileRepo.GetByAccountID(ctx, id); err == nil && profile != nil && profile.Nickname == old {
		profile.UpdateNickname(username)
		_ = uc.profileRepo.Update(ctx, profile)
	}

	_ = uc.eventPublisher.PublishAccountUsernameChanged(ctx, acc, old)
	return nil
}

/* ---------- Работа с паролями ---------- */

func (uc *AccountUseCaseImpl) ChangePassword(ctx context.Context, id uuid.UUID, oldPwd, newPwd string) error {
	acc, err := uc.accountRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	var pwdAM *entity.AuthMethod
	if ams, err := uc.authMethodRepo.GetByAccountID(ctx, id); err == nil {
		for _, am := range ams {
			if am.Type == entity.AuthMethodTypePassword {
				pwdAM = am
				break
			}
		}
	}
	if pwdAM == nil {
		return errors.New("password auth method not found")
	}

	if !uc.passwordHasher.VerifyPassword(oldPwd, pwdAM.Secret) {
		return errors.New("invalid old password")
	}

	hashed, err := uc.passwordHasher.HashPassword(newPwd)
	if err != nil {
		return err
	}
	pwdAM.UpdateSecret(hashed)
	if err := uc.authMethodRepo.Update(ctx, pwdAM); err != nil {
		return err
	}

	_ = uc.eventPublisher.PublishAccountPasswordChanged(ctx, acc)
	_ = uc.notifyClient.SendPasswordChangedNotification(ctx, acc.ID)
	return nil
}

func (uc *AccountUseCaseImpl) ResetPassword(ctx context.Context, id uuid.UUID, token, newPwd string) error {
	if !uc.tokenGenerator.VerifyToken(token) {
		return errors.New("invalid or expired token")
	}

	acc, err := uc.accountRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	var pwdAM *entity.AuthMethod
	if ams, err := uc.authMethodRepo.GetByAccountID(ctx, id); err == nil {
		for _, am := range ams {
			if am.Type == entity.AuthMethodTypePassword {
				pwdAM = am
				break
			}
		}
	}
	if pwdAM == nil {
		return errors.New("password auth method not found")
	}

	hashed, err := uc.passwordHasher.HashPassword(newPwd)
	if err != nil {
		return err
	}
	pwdAM.UpdateSecret(hashed)
	if err := uc.authMethodRepo.Update(ctx, pwdAM); err != nil {
		return err
	}

	_ = uc.eventPublisher.PublishAccountPasswordReset(ctx, acc)
	_ = uc.notifyClient.SendPasswordResetCompletedNotification(ctx, acc.ID)
	return nil
}

func (uc *AccountUseCaseImpl) RequestPasswordReset(ctx context.Context, email string) error {
	acc, err := uc.accountRepo.GetByEmail(ctx, email)
	if err != nil {
		return err
	}

	token, err := uc.tokenGenerator.GenerateToken()
	if err != nil {
		return err
	}

	if err := uc.notifyClient.SendPasswordResetNotification(ctx, acc.ID, token); err != nil {
		return err
	}

	_ = uc.eventPublisher.PublishAccountPasswordResetRequested(ctx, acc)
	return nil
}

/* ---------- Верификация e‑mail ---------- */

func (uc *AccountUseCaseImpl) VerifyEmail(ctx context.Context, id uuid.UUID, code string) error {
	acc, err := uc.accountRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	var emailCI *entity.ContactInfo
	if cis, err := uc.contactInfoRepo.GetByAccountIDAndType(ctx, id, entity.ContactTypeEmail); err == nil {
		for _, ci := range cis {
			if ci.Value == acc.Email {
				emailCI = ci
				break
			}
		}
	}
	if emailCI == nil {
		return errors.New("email contact not found")
	}

	if !emailCI.VerifyCode(code) {
		_ = uc.contactInfoRepo.IncrementVerificationAttempts(ctx, emailCI.ID)
		return errors.New("invalid verification code")
	}

	if err := uc.contactInfoRepo.Verify(ctx, emailCI.ID); err != nil {
		return err
	}

	_ = uc.eventPublisher.PublishAccountEmailVerified(ctx, acc)
	return nil
}

func (uc *AccountUseCaseImpl) SendVerificationEmail(ctx context.Context, id uuid.UUID) error {
	acc, err := uc.accountRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	var emailCI *entity.ContactInfo
	if cis, err := uc.contactInfoRepo.GetByAccountIDAndType(ctx, id, entity.ContactTypeEmail); err == nil {
		for _, ci := range cis {
			if ci.Value == acc.Email {
				emailCI = ci
				break
			}
		}
	}
	if emailCI == nil {
		return errors.New("email contact not found")
	}

	code := uc.tokenGenerator.GenerateVerificationCode()
	if err := uc.contactInfoRepo.SetVerificationCode(ctx, emailCI.ID, code, 30); err != nil {
		return err
	}

	return uc.notifyClient.SendEmailVerificationNotification(ctx, acc.ID, code)
}

/* ---------- Поиск ---------- */

func (uc *AccountUseCaseImpl) SearchAccounts(ctx context.Context, query string, limit, offset int) ([]*entity.Account, int64, error) {
	filter := repository.AccountFilter{
		Username:  query,
		Email:     query,
		Limit:     limit,
		Offset:    offset,
		SortBy:    "created_at",
		SortOrder: "desc",
	}
	return uc.accountRepo.List(ctx, filter)
}
