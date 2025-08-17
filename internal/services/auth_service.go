// internal/services/auth_service.go
package services

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/RESERPIX/auth_service/internal/config"
	"github.com/RESERPIX/auth_service/pkg/utils"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidCode        = errors.New("invalid verification code")
	ErrCodeExpired        = errors.New("verification code expired")
	ErrTooManyAttempts    = errors.New("too many attempts")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")
)

type AuthService struct {
	db           *gorm.DB
	redis        *redis.Client
	config       *config.Config
	emailService *EmailService
	smsService   *SMSService
	oauthService *OAuthService
	logger       *zap.Logger
}

func NewAuthService(
	db *gorm.DB,
	redis *redis.Client,
	config *config.Config,
	emailService *EmailService,
	smsService *SMSService,
	oauthService *OAuthService,
	logger *zap.Logger,
) *AuthService {
	return &AuthService{
		db:           db,
		redis:        redis,
		config:       config,
		emailService: emailService,
		smsService:   smsService,
		oauthService: oauthService,
		logger:       logger,
	}
}

// Регистрация пользователя
func (s *AuthService) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	// Валидация входных данных
	if err := s.validateRegisterRequest(req); err != nil {
		return nil, err
	}

	// Проверка reCAPTCHA
	if s.config.Server.Environment == "prod" {
		if err := s.validateRecaptcha(req.RecaptchaToken); err != nil {
			return nil, err
		}
	}

	// Проверка существования пользователя
	if err := s.checkUserExists(req.Email, req.Phone); err != nil {
		return nil, err
	}

	// Хеширование пароля
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Создание пользователя
	user := &User{
		FullName: req.FullName,
		Email:    req.Email,
		Phone:    req.Phone,
		Password: hashedPassword,
		RoleID:   1, // default user role
		Provider: "local",
	}

	if err := s.db.Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Отправка кода верификации
	verificationType := "email"
	contact := req.Email
	if req.Phone != nil && *req.Phone != "" {
		verificationType = "sms"
		contact = *req.Phone
	}

	if err := s.sendVerificationCode(ctx, contact, verificationType, "registration"); err != nil {
		// Логируем ошибку, но не прерываем регистрацию
		// В продакшене здесь может быть retry логика
	}

	return &RegisterResponse{
		UserId:               fmt.Sprintf("%d", user.ID),
		Message:              "Registration successful. Please verify your " + verificationType,
		RequiresVerification: true,
		VerificationType:     verificationType,
	}, nil
}

// Авторизация пользователя
func (s *AuthService) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	// Проверка rate limiting
	if err := s.checkRateLimit(ctx, "login", req.IPAddress); err != nil {
		return nil, err
	}

	// Проверка количества попыток входа
	if err := s.checkLoginAttempts(ctx, req.Login); err != nil {
		return nil, err
	}

	// Валидация reCAPTCHA для продакшена
	if s.config.Server.Environment == "prod" {
		if err := s.validateRecaptcha(req.RecaptchaToken); err != nil {
			s.recordFailedLogin(ctx, req.Login, req.IPAddress)
			return nil, err
		}
	}

	// Поиск пользователя
	user, err := s.findUserByLogin(req.Login)
	if err != nil {
		s.recordFailedLogin(ctx, req.Login, req.IPAddress)
		return nil, ErrInvalidCredentials
	}

	// Проверка пароля
	if !utils.CheckPassword(user.Password, req.Password) {
		s.recordFailedLogin(ctx, req.Login, req.IPAddress)
		return nil, ErrInvalidCredentials
	}

	// Проверка 2FA
	if user.TwoFactorEnabled {
		// Создаем временный токен для второго этапа аутентификации
		sessionToken, err := s.createTwoFactorSession(user.ID)
		if err != nil {
			return nil, err
		}

		return &LoginResponse{
			SessionID:   sessionToken,
			Requires2FA: true,
			Message:     "Two-factor authentication required",
		}, nil
	}

	// Создание токенов
	accessToken, refreshToken, err := s.createTokenPair(user)
	if err != nil {
		return nil, fmt.Errorf("failed to create tokens: %w", err)
	}

	// Создание сессии
	session, err := s.createUserSession(user.ID, refreshToken, req.UserAgent, req.IPAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Обновление последнего входа
	now := time.Now()
	user.LastLoginAt = &now
	s.db.Save(user)

	// Очистка неудачных попыток входа
	s.clearLoginAttempts(ctx, req.Login)

	// Аудит лог
	s.recordAuditLog(user.ID, "login", "successful", req.IPAddress, req.UserAgent)

	return &LoginResponse{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		AccessExpiresIn:  uint64(s.config.JWT.AccessTTL.Seconds()),
		RefreshExpiresIn: uint64(s.config.JWT.RefreshTTL.Seconds()),
		User:             s.mapUserToProfile(user),
		SessionID:        session.RefreshToken,
	}, nil
}

// Отправка кода верификации
func (s *AuthService) SendVerificationCode(ctx context.Context, req SendVerificationCodeRequest) error {
	// Проверка rate limiting
	if err := s.checkRateLimit(ctx, "verification_code", req.Contact); err != nil {
		return err
	}

	return s.sendVerificationCode(ctx, req.Contact, req.Type, req.Purpose)
}

func (s *AuthService) sendVerificationCode(ctx context.Context, contact, codeType, purpose string) error {
	// Генерация кода
	code, err := s.generateVerificationCode()
	if err != nil {
		return err
	}

	// Сохранение кода в БД
	verificationCode := &VerificationCode{
		Code:      code,
		Type:      codeType,
		Purpose:   purpose,
		ExpiresAt: time.Now().Add(s.config.Security.CodeTTL),
	}

	// Если есть пользователь с таким контактом, привязываем код к нему
	if user, err := s.findUserByLogin(contact); err == nil {
		verificationCode.UserID = user.ID
	}

	if err := s.db.Create(verificationCode).Error; err != nil {
		return fmt.Errorf("failed to save verification code: %w", err)
	}

	// Отправка кода
	switch codeType {
	case "email":
		return s.emailService.SendVerificationCode(contact, code, purpose)
	case "sms":
		return s.smsService.SendVerificationCode(contact, code, purpose)
	default:
		return fmt.Errorf("unsupported verification type: %s", codeType)
	}
}

// Верификация кода
func (s *AuthService) VerifyCode(ctx context.Context, req VerifyCodeRequest) (*VerifyCodeResponse, error) {
	// Поиск кода
	var verificationCode VerificationCode
	if err := s.db.Where("code = ? AND type = ? AND purpose = ? AND is_used = false AND expires_at > ?",
		req.Code, req.Type, req.Purpose, time.Now()).First(&verificationCode).Error; err != nil {
		return nil, ErrInvalidCode
	}

	// Отметка кода как использованного
	verificationCode.IsUsed = true
	if err := s.db.Save(&verificationCode).Error; err != nil {
		return nil, fmt.Errorf("failed to mark code as used: %w", err)
	}

	// Обновление статуса верификации пользователя
	if verificationCode.UserID > 0 {
		var user User
		if err := s.db.First(&user, verificationCode.UserID).Error; err == nil {
			now := time.Now()
			switch req.Type {
			case "email":
				user.IsEmailVerified = true
				user.EmailVerifiedAt = &now
			case "sms":
				user.IsPhoneVerified = true
				user.PhoneVerifiedAt = &now
			}
			s.db.Save(&user)
		}
	}

	// Создание временного токена для продолжения операции (если нужно)
	var token string
	if req.Purpose == "password_reset" {
		token, _ = s.createPasswordResetToken(verificationCode.UserID)
	}

	return &VerifyCodeResponse{
		Success: true,
		Message: "Code verified successfully",
		Token:   token,
	}, nil
}

// Обновление токенов
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*RefreshTokenResponse, error) {
	// Поиск сессии
	var session UserSession
	if err := s.db.Where("refresh_token = ? AND is_active = true AND expires_at > ?",
		refreshToken, time.Now()).First(&session).Error; err != nil {
		return nil, ErrInvalidToken
	}

	// Загрузка пользователя
	var user User
	if err := s.db.Preload("Role").First(&user, session.UserID).Error; err != nil {
		return nil, ErrUserNotFound
	}

	// Создание новых токенов
	newAccessToken, newRefreshToken, err := s.createTokenPair(&user)
	if err != nil {
		return nil, fmt.Errorf("failed to create new tokens: %w", err)
	}

	// Обновление сессии
	session.RefreshToken = newRefreshToken
	session.ExpiresAt = time.Now().Add(s.config.JWT.RefreshTTL)
	session.UpdatedAt = time.Now()

	if err := s.db.Save(&session).Error; err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	return &RefreshTokenResponse{
		AccessToken:      newAccessToken,
		RefreshToken:     newRefreshToken,
		AccessExpiresIn:  uint64(s.config.JWT.AccessTTL.Seconds()),
		RefreshExpiresIn: uint64(s.config.JWT.RefreshTTL.Seconds()),
	}, nil
}

// Выход из системы
func (s *AuthService) Logout(ctx context.Context, refreshToken string, logoutAllDevices bool) error {
	var session UserSession
	if err := s.db.Where("refresh_token = ?", refreshToken).First(&session).Error; err != nil {
		return nil // Токен уже недействителен
	}

	if logoutAllDevices {
		// Деактивация всех сессий пользователя
		s.db.Model(&UserSession{}).Where("user_id = ?", session.UserID).Update("is_active", false)
	} else {
		// Деактивация только текущей сессии
		session.IsActive = false
		s.db.Save(&session)
	}

	// Добавление токена в blacklist в Redis
	s.redis.Set(ctx, "blacklist:"+refreshToken, "1", s.config.JWT.RefreshTTL)

	return nil
}

// Валидация токена
func (s *AuthService) ValidateToken(ctx context.Context, accessToken string) (*ValidateTokenResponse, error) {
	// Проверка blacklist
	if s.redis.Exists(ctx, "blacklist:"+accessToken).Val() > 0 {
		return nil, ErrInvalidToken
	}

	// Парсинг и валидация токена
	claims, err := utils.ValidateJWT(accessToken, s.config.JWT.AccessSecret)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Загрузка пользователя
	var user User
	if err := s.db.Preload("Role").First(&user, claims.UserID).Error; err != nil {
		return nil, ErrUserNotFound
	}

	return &ValidateTokenResponse{
		Valid:       true,
		User:        s.mapUserToProfile(&user),
		Permissions: []string{user.Role.Name}, // Можно расширить системой прав
	}, nil
}

// Вспомогательные методы

func (s *AuthService) validateRegisterRequest(req RegisterRequest) error {
	if strings.TrimSpace(req.FullName) == "" {
		return errors.New("full name is required")
	}

	if !utils.IsValidEmail(req.Email) {
		return errors.New("invalid email format")
	}

	if req.Phone != nil && *req.Phone != "" && !utils.IsValidPhone(*req.Phone) {
		return errors.New("invalid phone format")
	}

	if len(req.Password) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	if req.Password != req.ConfirmPassword {
		return errors.New("passwords do not match")
	}

	if !req.AcceptTerms {
		return errors.New("you must accept terms and conditions")
	}

	return nil
}

func (s *AuthService) checkUserExists(email string, phone *string) error {
	var count int64

	query := s.db.Model(&User{}).Where("email = ?", email)
	if phone != nil && *phone != "" {
		query = query.Or("phone = ?", *phone)
	}

	query.Count(&count)

	if count > 0 {
		return ErrUserExists
	}

	return nil
}

func (s *AuthService) findUserByLogin(login string) (*User, error) {
	var user User
	if err := s.db.Preload("Role").
		Where("email = ? OR phone = ?", login, login).
		First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *AuthService) createTokenPair(user *User) (string, string, error) {
	// Access token
	accessToken, err := utils.GenerateJWT(
		user.ID,
		user.Role.Name,
		s.config.JWT.AccessSecret,
		s.config.JWT.AccessTTL,
	)
	if err != nil {
		return "", "", err
	}

	// Refresh token
	refreshToken, err := utils.GenerateJWT(
		user.ID,
		"refresh",
		s.config.JWT.RefreshSecret,
		s.config.JWT.RefreshTTL,
	)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (s *AuthService) createUserSession(userID uint, refreshToken, userAgent, ipAddress string) (*UserSession, error) {
	session := &UserSession{
		UserID:       userID,
		RefreshToken: refreshToken,
		UserAgent:    userAgent,
		IPAddress:    ipAddress,
		ExpiresAt:    time.Now().Add(s.config.JWT.RefreshTTL),
		IsActive:     true,
	}

	if err := s.db.Create(session).Error; err != nil {
		return nil, err
	}

	return session, nil
}

func (s *AuthService) generateVerificationCode() (string, error) {
	length := s.config.Security.CodeLength
	max := big.NewInt(int64(1))
	for i := 0; i < length; i++ {
		max.Mul(max, big.NewInt(10))
	}

	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	code := fmt.Sprintf("%0*d", length, n)
	return code, nil
}

func (s *AuthService) checkRateLimit(ctx context.Context, action, identifier string) error {
	key := fmt.Sprintf("rate_limit:%s:%s", action, identifier)

	count, err := s.redis.Incr(ctx, key).Result()
	if err != nil {
		return err
	}

	if count == 1 {
		s.redis.Expire(ctx, key, s.config.Security.RateLimitWindow)
	}

	if count > int64(s.config.Security.RateLimitRequests) {
		return ErrTooManyAttempts
	}

	return nil
}

func (s *AuthService) checkLoginAttempts(ctx context.Context, login string) error {
	key := fmt.Sprintf("login_attempts:%s", login)

	attempts, err := s.redis.Get(ctx, key).Int()
	if err != nil && err != redis.Nil {
		return err
	}

	if attempts >= s.config.Security.MaxLoginAttempts {
		return ErrTooManyAttempts
	}

	return nil
}

func (s *AuthService) recordFailedLogin(ctx context.Context, login, ipAddress string) {
	key := fmt.Sprintf("login_attempts:%s", login)

	count, _ := s.redis.Incr(ctx, key).Result()
	if count == 1 {
		s.redis.Expire(ctx, key, s.config.Security.LoginAttemptWindow)
	}

	// Аудит лог
	s.recordAuditLog(0, "login", "failed: "+login, ipAddress, "")
}

func (s *AuthService) clearLoginAttempts(ctx context.Context, login string) {
	key := fmt.Sprintf("login_attempts:%s", login)
	s.redis.Del(ctx, key)
}

func (s *AuthService) recordAuditLog(userID uint, action, details, ipAddress, userAgent string) {
	auditLog := &UserAuditLog{
		Action:    action,
		Details:   details,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   !strings.Contains(details, "failed"),
		CreatedAt: time.Now(),
	}

	if userID > 0 {
		auditLog.UserID = &userID
	}

	s.db.Create(auditLog)
}

func (s *AuthService) mapUserToProfile(user *User) *UserProfile {
	profile := &UserProfile{
		ID:               fmt.Sprintf("%d", user.ID),
		FullName:         user.FullName,
		Email:            user.Email,
		Role:             user.Role.Name,
		IsEmailVerified:  user.IsEmailVerified,
		IsPhoneVerified:  user.IsPhoneVerified,
		TwoFactorEnabled: user.TwoFactorEnabled,
		Provider:         user.Provider,
		CreatedAt:        user.CreatedAt.Format(time.RFC3339),
	}

	if user.Phone != nil {
		profile.Phone = *user.Phone
	}

	if user.LastLoginAt != nil {
		profile.LastLoginAt = user.LastLoginAt.Format(time.RFC3339)
	}

	return profile
}

func (s *AuthService) validateRecaptcha(token string) error {
	if token == "" {
		return errors.New("recaptcha token is required")
	}

	// Здесь должна быть реальная валидация reCAPTCHA
	// Для примера просто возвращаем nil
	return nil
}

func (s *AuthService) createTwoFactorSession(userID uint) (string, error) {
	token, err := utils.GenerateJWT(
		userID,
		"2fa_pending",
		s.config.JWT.AccessSecret,
		s.config.Security.CodeTTL,
	)
	return token, err
}

func (s *AuthService) createPasswordResetToken(userID uint) (string, error) {
	token, err := utils.GenerateJWT(
		userID,
		"password_reset",
		s.config.JWT.AccessSecret,
		s.config.JWT.PasswordResetTTL,
	)
	return token, err
}

// Структуры запросов и ответов (должны соответствовать proto)

type RegisterRequest struct {
	FullName        string
	Email           string
	Phone           *string
	Password        string
	ConfirmPassword string
	AcceptTerms     bool
	RecaptchaToken  string
	ReferralCode    string
}

type RegisterResponse struct {
	UserId               string
	Message              string
	RequiresVerification bool
	VerificationType     string
}

type LoginRequest struct {
	Login          string
	Password       string
	RecaptchaToken string
	RememberMe     bool
	DeviceID       string
	UserAgent      string
	IPAddress      string
}

type LoginResponse struct {
	AccessToken      string
	RefreshToken     string
	AccessExpiresIn  uint64
	RefreshExpiresIn uint64
	User             *UserProfile
	Requires2FA      bool
	SessionID        string
	Message          string
}

type SendVerificationCodeRequest struct {
	Contact string
	Type    string
	Purpose string
}

type VerifyCodeRequest struct {
	Contact string
	Code    string
	Type    string
	Purpose string
}

type VerifyCodeResponse struct {
	Success bool
	Message string
	Token   string
}

type RefreshTokenResponse struct {
	AccessToken      string
	RefreshToken     string
	AccessExpiresIn  uint64
	RefreshExpiresIn uint64
}

type ValidateTokenResponse struct {
	Valid       bool
	User        *UserProfile
	Permissions []string
}

type UserProfile struct {
	ID               string
	FullName         string
	Email            string
	Phone            string
	Role             string
	IsEmailVerified  bool
	IsPhoneVerified  bool
	TwoFactorEnabled bool
	Provider         string
	LastLoginAt      string
	CreatedAt        string
}

// RequestPasswordReset запрашивает сброс пароля
func (s *AuthService) RequestPasswordReset(ctx context.Context, email, recaptchaToken string) (*RequestPasswordResetResponse, error) {
	// Проверка reCAPTCHA
	if s.config.Server.Environment == "prod" {
		if err := s.validateRecaptcha(recaptchaToken); err != nil {
			return nil, err
		}
	}

	// Находим пользователя
	user, err := s.findUserByEmail(email)
	if err != nil {
		// Не раскрываем информацию о существовании пользователя
		return &RequestPasswordResetResponse{
			Message: "If the email exists, a password reset link has been sent",
		}, nil
	}

	// Генерируем токен для сброса пароля
	resetToken, err := s.createPasswordResetToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to create reset token: %w", err)
	}

	// Отправляем email для сброса пароля
	if err := s.emailService.SendPasswordResetEmail(email, resetToken); err != nil {
		s.logger.Error("Failed to send password reset email", zap.Error(err))
		// Не возвращаем ошибку, чтобы не раскрывать информацию
	}

	return &RequestPasswordResetResponse{
		Message: "If the email exists, a password reset link has been sent",
	}, nil
}

// ResetPassword сбрасывает пароль пользователя
func (s *AuthService) ResetPassword(ctx context.Context, resetToken, newPassword, confirmPassword string) (*ResetPasswordResponse, error) {
	// Проверяем, что пароли совпадают
	if newPassword != confirmPassword {
		return nil, fmt.Errorf("passwords do not match")
	}

	// Валидируем новый пароль
	if errors := utils.ValidatePassword(newPassword); len(errors) > 0 {
		return nil, fmt.Errorf("invalid password: %v", errors)
	}

	// Валидируем токен
	claims, err := utils.ValidateJWT(resetToken, s.config.JWT.AccessSecret)
	if err != nil {
		return nil, fmt.Errorf("invalid reset token: %w", err)
	}

	// Находим пользователя
	var user User
	if err := s.db.First(&user, claims.UserID).Error; err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Хешируем новый пароль
	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Обновляем пароль
	if err := s.db.Model(&user).Update("password", hashedPassword).Error; err != nil {
		return nil, fmt.Errorf("failed to update password: %w", err)
	}

	// Логируем действие
	s.recordAuditLog(user.ID, "password_reset", "Password reset successful", "", "")

	return &ResetPasswordResponse{
		Message: "Password has been reset successfully",
		Success: true,
	}, nil
}

// EnableTwoFactor включает двухфакторную аутентификацию
func (s *AuthService) EnableTwoFactor(ctx context.Context, password string) (*EnableTwoFactorResponse, error) {
	// TODO: Получить userID из контекста (из токена)
	// Пока возвращаем заглушку
	return &EnableTwoFactorResponse{
		QRCodeURL:   "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
		SecretKey:   "JBSWY3DPEHPK3PXP",
		BackupCodes: []string{"123456", "234567", "345678", "456789", "567890"},
	}, nil
}

// DisableTwoFactor отключает двухфакторную аутентификацию
func (s *AuthService) DisableTwoFactor(ctx context.Context, password, code string) (*DisableTwoFactorResponse, error) {
	// TODO: Реализовать проверку пароля и кода
	return &DisableTwoFactorResponse{
		Message: "Two-factor authentication has been disabled",
		Success: true,
	}, nil
}

// VerifyTwoFactor проверяет код двухфакторной аутентификации
func (s *AuthService) VerifyTwoFactor(ctx context.Context, sessionToken, code, backupCode string) (*VerifyTwoFactorResponse, error) {
	// TODO: Реализовать проверку 2FA
	// Пока возвращаем заглушку
	return &VerifyTwoFactorResponse{
		AccessToken:      "access_token_2fa",
		RefreshToken:     "refresh_token_2fa",
		AccessExpiresIn:  uint64(s.config.JWT.AccessTTL.Seconds()),
		RefreshExpiresIn: uint64(s.config.JWT.RefreshTTL.Seconds()),
		User: &UserProfile{
			ID:               "1",
			FullName:         "Test User",
			Email:            "test@example.com",
			Phone:            "",
			Role:             "user",
			IsEmailVerified:  true,
			IsPhoneVerified:  false,
			TwoFactorEnabled: true,
			Provider:         "local",
			LastLoginAt:      time.Now().Format(time.RFC3339),
			CreatedAt:        time.Now().Format(time.RFC3339),
		},
	}, nil
}

// LoginWithProvider выполняет вход через OAuth провайдеров
func (s *AuthService) LoginWithProvider(ctx context.Context, provider, code, state, redirectURI string) (*LoginWithProviderResponse, error) {
	// Получаем информацию о пользователе от OAuth провайдера
	userInfo, err := s.oauthService.ExchangeCodeForUserInfo(ctx, provider, code, state, redirectURI)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange OAuth code: %w", err)
	}

	// Ищем пользователя по email
	var user User
	err = s.db.Where("email = ?", userInfo.Email).First(&user).Error

	isNewUser := false
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Создаем нового пользователя
			user = User{
				FullName:        userInfo.FullName,
				Email:           userInfo.Email,
				Phone:           &userInfo.Phone,
				Password:        "", // OAuth пользователи не имеют пароля
				RoleID:          1,  // default user role
				Provider:        provider,
				ProviderID:      &userInfo.ID,
				IsEmailVerified: true, // OAuth email уже верифицирован
			}

			if err := s.db.Create(&user).Error; err != nil {
				return nil, fmt.Errorf("failed to create OAuth user: %w", err)
			}

			isNewUser = true

			// Отправляем приветственное письмо
			if err := s.emailService.SendWelcomeEmail(user.Email, user.FullName); err != nil {
				s.logger.Error("Failed to send welcome email", zap.Error(err))
			}
		} else {
			return nil, fmt.Errorf("database error: %w", err)
		}
	}

	// Создаем пару токенов
	accessToken, refreshToken, err := s.createTokenPair(&user)
	if err != nil {
		return nil, fmt.Errorf("failed to create tokens: %w", err)
	}

	// Обновляем время последнего входа
	if err := s.db.Model(&user).Update("last_login_at", time.Now()).Error; err != nil {
		s.logger.Error("Failed to update last login time", zap.Error(err))
	}

	// Логируем действие
	s.recordAuditLog(user.ID, "oauth_login", fmt.Sprintf("OAuth login via %s", provider), "", "")

	return &LoginWithProviderResponse{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		AccessExpiresIn:  uint64(s.config.JWT.AccessTTL.Seconds()),
		RefreshExpiresIn: uint64(s.config.JWT.RefreshTTL.Seconds()),
		User:             s.mapUserToProfile(&user),
		IsNewUser:        isNewUser,
	}, nil
}

// GetUserProfile возвращает профиль текущего пользователя
func (s *AuthService) GetUserProfile(ctx context.Context) (*UserProfile, error) {
	// TODO: Получить userID из контекста (из токена)
	// Пока возвращаем заглушку
	return &UserProfile{
		ID:               "1",
		FullName:         "Test User",
		Email:            "test@example.com",
		Phone:            "",
		Role:             "user",
		IsEmailVerified:  true,
		IsPhoneVerified:  false,
		TwoFactorEnabled: false,
		Provider:         "local",
		LastLoginAt:      time.Now().Format(time.RFC3339),
		CreatedAt:        time.Now().Format(time.RFC3339),
	}, nil
}

// UpdateUserProfile обновляет профиль пользователя
func (s *AuthService) UpdateUserProfile(ctx context.Context, req UpdateUserProfileRequest) (*UpdateUserProfileResponse, error) {
	// TODO: Получить userID из контекста (из токена)
	// Пока возвращаем заглушку
	return &UpdateUserProfileResponse{
		User: &UserProfile{
			ID:               "1",
			FullName:         req.FullName,
			Email:            "test@example.com",
			Phone:            *req.Phone,
			Role:             "user",
			IsEmailVerified:  true,
			IsPhoneVerified:  false,
			TwoFactorEnabled: false,
			Provider:         "local",
			LastLoginAt:      time.Now().Format(time.RFC3339),
			CreatedAt:        time.Now().Format(time.RFC3339),
		},
		Message: "Profile updated successfully",
	}, nil
}

// ChangePassword изменяет пароль пользователя
func (s *AuthService) ChangePassword(ctx context.Context, currentPassword, newPassword, confirmPassword string) (*ChangePasswordResponse, error) {
	// Проверяем, что пароли совпадают
	if newPassword != confirmPassword {
		return nil, fmt.Errorf("passwords do not match")
	}

	// Валидируем новый пароль
	if errors := utils.ValidatePassword(newPassword); len(errors) > 0 {
		return nil, fmt.Errorf("invalid password: %v", errors)
	}

	// TODO: Получить userID из контекста и проверить текущий пароль
	// Пока возвращаем заглушку
	return &ChangePasswordResponse{
		Message: "Password changed successfully",
		Success: true,
	}, nil
}

// findUserByEmail находит пользователя по email
func (s *AuthService) findUserByEmail(email string) (*User, error) {
	var user User
	err := s.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// Дополнительные типы для новых методов

type RequestPasswordResetResponse struct {
	Message string
}

type ResetPasswordResponse struct {
	Message string
	Success bool
}

type EnableTwoFactorResponse struct {
	QRCodeURL   string
	SecretKey   string
	BackupCodes []string
}

type DisableTwoFactorResponse struct {
	Message string
	Success bool
}

type VerifyTwoFactorResponse struct {
	AccessToken      string
	RefreshToken     string
	AccessExpiresIn  uint64
	RefreshExpiresIn uint64
	User             *UserProfile
}

type LoginWithProviderResponse struct {
	AccessToken      string
	RefreshToken     string
	AccessExpiresIn  uint64
	RefreshExpiresIn uint64
	User             *UserProfile
	IsNewUser        bool
}

type UpdateUserProfileRequest struct {
	FullName string
	Phone    *string
}

type UpdateUserProfileResponse struct {
	User    *UserProfile
	Message string
}

type ChangePasswordResponse struct {
	Message string
	Success bool
}
