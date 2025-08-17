package app

import (
	"context"

	pb "github.com/RESERPIX/auth_service/internal/pb/proto/auth"
	"github.com/RESERPIX/auth_service/internal/services"
	"github.com/RESERPIX/auth_service/pkg/locale"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthServer struct {
	pb.UnimplementedAuthServiceServer
	AuthService *services.AuthService
	Logger      *zap.Logger
}

// NewAuthServer создает новый экземпляр AuthServer
func NewAuthServer(authService *services.AuthService, logger *zap.Logger) *AuthServer {
	return &AuthServer{
		AuthService: authService,
		Logger:      logger,
	}
}

// Register реализует регистрацию пользователя
func (s *AuthServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	s.Logger.Info("Register request received", zap.String("email", req.Email))

	// Конвертируем protobuf запрос в внутренний формат
	registerReq := services.RegisterRequest{
		FullName:        req.FullName,
		Email:           req.Email,
		Phone:           &req.Phone,
		Password:        req.Password,
		ConfirmPassword: req.ConfirmPassword,
		AcceptTerms:     req.AcceptTerms,
		RecaptchaToken:  req.RecaptchaToken,
		ReferralCode:    req.ReferralCode,
	}

	// Вызываем сервис
	resp, err := s.AuthService.Register(ctx, registerReq)
	if err != nil {
		s.Logger.Error("Registration failed", zap.Error(err))
		return nil, status.Errorf(codes.Internal, locale.Get("registration_failed")+": %v", err)
	}

	// Конвертируем ответ в protobuf формат
	return &pb.RegisterResponse{
		UserId:               resp.UserId,
		Message:              resp.Message,
		RequiresVerification: resp.RequiresVerification,
		VerificationType:     resp.VerificationType,
	}, nil
}

// Login реализует вход пользователя
func (s *AuthServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	s.Logger.Info("Login request received", zap.String("login", req.Login))

	// Конвертируем protobuf запрос в внутренний формат
	loginReq := services.LoginRequest{
		Login:          req.Login,
		Password:       req.Password,
		RecaptchaToken: req.RecaptchaToken,
		RememberMe:     req.RememberMe,
		DeviceID:       req.DeviceId,
		UserAgent:      req.UserAgent,
		IPAddress:      req.IpAddress,
	}

	// Вызываем сервис
	resp, err := s.AuthService.Login(ctx, loginReq)
	if err != nil {
		s.Logger.Error("Login failed", zap.Error(err))
		return nil, status.Errorf(codes.Unauthenticated, locale.Get("login_failed")+": %v", err)
	}

	// Конвертируем ответ в protobuf формат
	return &pb.LoginResponse{
		AccessToken:      resp.AccessToken,
		RefreshToken:     resp.RefreshToken,
		AccessExpiresIn:  resp.AccessExpiresIn,
		RefreshExpiresIn: resp.RefreshExpiresIn,
		User: &pb.UserProfile{
			Id:               resp.User.ID,
			FullName:         resp.User.FullName,
			Email:            resp.User.Email,
			Phone:            resp.User.Phone,
			Role:             resp.User.Role,
			IsEmailVerified:  resp.User.IsEmailVerified,
			IsPhoneVerified:  resp.User.IsPhoneVerified,
			TwoFactorEnabled: resp.User.TwoFactorEnabled,
			Provider:         resp.User.Provider,
			LastLoginAt:      resp.User.LastLoginAt,
			CreatedAt:        resp.User.CreatedAt,
		},
		Requires_2Fa: resp.Requires2FA,
		SessionId:   resp.SessionID,
	}, nil
}

// RefreshToken реализует обновление токенов
func (s *AuthServer) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	s.Logger.Info("Refresh token request received")

	// Вызываем сервис
	resp, err := s.AuthService.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		s.Logger.Error("Token refresh failed", zap.Error(err))
		return nil, status.Errorf(codes.Unauthenticated, locale.Get("token_invalid")+": %v", err)
	}

	// Конвертируем ответ в protobuf формат
	return &pb.RefreshTokenResponse{
		AccessToken:      resp.AccessToken,
		RefreshToken:     resp.RefreshToken,
		AccessExpiresIn:  resp.AccessExpiresIn,
		RefreshExpiresIn: resp.RefreshExpiresIn,
	}, nil
}

// Logout реализует выход пользователя
func (s *AuthServer) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	s.Logger.Info("Logout request received")

	// Вызываем сервис
	err := s.AuthService.Logout(ctx, req.RefreshToken, req.LogoutAllDevices)
	if err != nil {
		s.Logger.Error("Logout failed", zap.Error(err))
		return nil, status.Errorf(codes.Internal, locale.Get("logout_failed")+": %v", err)
	}

	// Конвертируем ответ в protobuf формат
	return &pb.LogoutResponse{
		Message: "Logout successful",
	}, nil
}

// SendVerificationCode реализует отправку кода верификации
func (s *AuthServer) SendVerificationCode(ctx context.Context, req *pb.SendVerificationCodeRequest) (*pb.SendVerificationCodeResponse, error) {
	s.Logger.Info("Send verification code request received", zap.String("contact", req.Contact))

	// Конвертируем protobuf запрос в внутренний формат
	sendCodeReq := services.SendVerificationCodeRequest{
		Contact: req.Contact,
		Type:    req.Type,
		Purpose: req.Purpose,
	}

	// Вызываем сервис
	err := s.AuthService.SendVerificationCode(ctx, sendCodeReq)
	if err != nil {
		s.Logger.Error("Failed to send verification code", zap.Error(err))
		return nil, status.Errorf(codes.Internal, locale.Get("verification_failed")+": %v", err)
	}

	// Конвертируем ответ в protobuf формат
	return &pb.SendVerificationCodeResponse{
		Message:   "Verification code sent successfully",
		ExpiresIn: 300, // 5 minutes
	}, nil
}

// VerifyCode реализует проверку кода верификации
func (s *AuthServer) VerifyCode(ctx context.Context, req *pb.VerifyCodeRequest) (*pb.VerifyCodeResponse, error) {
	s.Logger.Info("Verify code request received", zap.String("contact", req.Contact))

	// Конвертируем protobuf запрос в внутренний формат
	verifyCodeReq := services.VerifyCodeRequest{
		Contact: req.Contact,
		Code:    req.Code,
		Type:    req.Type,
		Purpose: req.Purpose,
	}

	// Вызываем сервис
	resp, err := s.AuthService.VerifyCode(ctx, verifyCodeReq)
	if err != nil {
		s.Logger.Error("Code verification failed", zap.Error(err))
		return nil, status.Errorf(codes.InvalidArgument, locale.Get("invalid_code")+": %v", err)
	}

	// Конвертируем ответ в protobuf формат
	return &pb.VerifyCodeResponse{
		Success: resp.Success,
		Message: resp.Message,
		Token:   resp.Token,
	}, nil
}

// RequestPasswordReset реализует запрос сброса пароля
func (s *AuthServer) RequestPasswordReset(ctx context.Context, req *pb.RequestPasswordResetRequest) (*pb.RequestPasswordResetResponse, error) {
	s.Logger.Info("Password reset request received", zap.String("email", req.Email))

	// Вызываем сервис
	resp, err := s.AuthService.RequestPasswordReset(ctx, req.Email, req.RecaptchaToken)
	if err != nil {
		s.Logger.Error("Password reset request failed", zap.Error(err))
		return nil, status.Errorf(codes.Internal, locale.Get("password_reset_failed")+": %v", err)
	}

	// Конвертируем ответ в protobuf формат
	return &pb.RequestPasswordResetResponse{
		Message: resp.Message,
	}, nil
}

// ResetPassword реализует сброс пароля
func (s *AuthServer) ResetPassword(ctx context.Context, req *pb.ResetPasswordRequest) (*pb.ResetPasswordResponse, error) {
	s.Logger.Info("Password reset request received")

	// Вызываем сервис
	resp, err := s.AuthService.ResetPassword(ctx, req.ResetToken, req.NewPassword, req.ConfirmPassword)
	if err != nil {
		s.Logger.Error("Password reset failed", zap.Error(err))
		return nil, status.Errorf(codes.Internal, locale.Get("password_reset_failed")+": %v", err)
	}

	// Конвертируем ответ в protobuf формат
	return &pb.ResetPasswordResponse{
		Message: resp.Message,
		Success: resp.Success,
	}, nil
}

// EnableTwoFactor реализует включение двухфакторной аутентификации
func (s *AuthServer) EnableTwoFactor(ctx context.Context, req *pb.EnableTwoFactorRequest) (*pb.EnableTwoFactorResponse, error) {
	s.Logger.Info("Enable 2FA request received")

	// Вызываем сервис
	resp, err := s.AuthService.EnableTwoFactor(ctx, req.Password)
	if err != nil {
		s.Logger.Error("Failed to enable 2FA", zap.Error(err))
		return nil, status.Errorf(codes.Internal, locale.Get("2fa_enable_failed")+": %v", err)
	}

	// Конвертируем ответ в protobuf формат
	return &pb.EnableTwoFactorResponse{
		QrCodeUrl:   resp.QRCodeURL,
		SecretKey:   resp.SecretKey,
		BackupCodes: resp.BackupCodes,
	}, nil
}

// DisableTwoFactor реализует отключение двухфакторной аутентификации
func (s *AuthServer) DisableTwoFactor(ctx context.Context, req *pb.DisableTwoFactorRequest) (*pb.DisableTwoFactorResponse, error) {
	s.Logger.Info("Disable 2FA request received")

	// Вызываем сервис
	resp, err := s.AuthService.DisableTwoFactor(ctx, req.Password, req.Code)
	if err != nil {
		s.Logger.Error("Failed to disable 2FA", zap.Error(err))
		return nil, status.Errorf(codes.Internal, locale.Get("2fa_disable_failed")+": %v", err)
	}

	// Конвертируем ответ в protobuf формат
	return &pb.DisableTwoFactorResponse{
		Message: resp.Message,
		Success: resp.Success,
	}, nil
}

// VerifyTwoFactor реализует проверку двухфакторной аутентификации
func (s *AuthServer) VerifyTwoFactor(ctx context.Context, req *pb.VerifyTwoFactorRequest) (*pb.VerifyTwoFactorResponse, error) {
	s.Logger.Info("Verify 2FA request received")

	// Вызываем сервис
	resp, err := s.AuthService.VerifyTwoFactor(ctx, req.SessionToken, req.Code, req.BackupCode)
	if err != nil {
		s.Logger.Error("2FA verification failed", zap.Error(err))
		return nil, status.Errorf(codes.Unauthenticated, locale.Get("2fa_code_invalid")+": %v", err)
	}

	// Конвертируем ответ в protobuf формат
	return &pb.VerifyTwoFactorResponse{
		AccessToken:      resp.AccessToken,
		RefreshToken:     resp.RefreshToken,
		AccessExpiresIn:  resp.AccessExpiresIn,
		RefreshExpiresIn: resp.RefreshExpiresIn,
		User: &pb.UserProfile{
			Id:               resp.User.ID,
			FullName:         resp.User.FullName,
			Email:            resp.User.Email,
			Phone:            resp.User.Phone,
			Role:             resp.User.Role,
			IsEmailVerified:  resp.User.IsEmailVerified,
			IsPhoneVerified:  resp.User.IsPhoneVerified,
			TwoFactorEnabled: resp.User.TwoFactorEnabled,
			Provider:         resp.User.Provider,
			LastLoginAt:      resp.User.LastLoginAt,
			CreatedAt:        resp.User.CreatedAt,
		},
	}, nil
}

// LoginWithProvider реализует вход через OAuth провайдеров
func (s *AuthServer) LoginWithProvider(ctx context.Context, req *pb.LoginWithProviderRequest) (*pb.LoginWithProviderResponse, error) {
	s.Logger.Info("OAuth login request received", zap.String("provider", req.Provider))

	// Вызываем сервис
	resp, err := s.AuthService.LoginWithProvider(ctx, req.Provider, req.Code, req.State, req.RedirectUri)
	if err != nil {
		s.Logger.Error("OAuth login failed", zap.Error(err))
		return nil, status.Errorf(codes.Unauthenticated, locale.Getf("oauth_login_failed", req.Provider)+": %v", err)
	}

	// Конвертируем ответ в protobuf формат
	return &pb.LoginWithProviderResponse{
		AccessToken:      resp.AccessToken,
		RefreshToken:     resp.RefreshToken,
		AccessExpiresIn:  resp.AccessExpiresIn,
		RefreshExpiresIn: resp.RefreshExpiresIn,
		User: &pb.UserProfile{
			Id:               resp.User.ID,
			FullName:         resp.User.FullName,
			Email:            resp.User.Email,
			Phone:            resp.User.Phone,
			Role:             resp.User.Role,
			IsEmailVerified:  resp.User.IsEmailVerified,
			IsPhoneVerified:  resp.User.IsPhoneVerified,
			TwoFactorEnabled: resp.User.TwoFactorEnabled,
			Provider:         resp.User.Provider,
			LastLoginAt:      resp.User.LastLoginAt,
			CreatedAt:        resp.User.CreatedAt,
		},
		IsNewUser: resp.IsNewUser,
	}, nil
}

// GetUserProfile реализует получение профиля пользователя
func (s *AuthServer) GetUserProfile(ctx context.Context, req *pb.GetUserProfileRequest) (*pb.GetUserProfileResponse, error) {
	s.Logger.Info("Get user profile request received")

	// Вызываем сервис
	userProfile, err := s.AuthService.GetUserProfile(ctx)
	if err != nil {
		s.Logger.Error("Failed to get user profile", zap.Error(err))
		return nil, status.Errorf(codes.Internal, locale.Get("profile_get_failed")+": %v", err)
	}

	// Конвертируем ответ в protobuf формат
	return &pb.GetUserProfileResponse{
		User: &pb.UserProfile{
			Id:               userProfile.ID,
			FullName:         userProfile.FullName,
			Email:            userProfile.Email,
			Phone:            userProfile.Phone,
			Role:             userProfile.Role,
			IsEmailVerified:  userProfile.IsEmailVerified,
			IsPhoneVerified:  userProfile.IsPhoneVerified,
			TwoFactorEnabled: userProfile.TwoFactorEnabled,
			Provider:         userProfile.Provider,
			LastLoginAt:      userProfile.LastLoginAt,
			CreatedAt:        userProfile.CreatedAt,
		},
	}, nil
}

// UpdateUserProfile реализует обновление профиля пользователя
func (s *AuthServer) UpdateUserProfile(ctx context.Context, req *pb.UpdateUserProfileRequest) (*pb.UpdateUserProfileResponse, error) {
	s.Logger.Info("Update user profile request received")

	// Конвертируем protobuf запрос в внутренний формат
	updateReq := services.UpdateUserProfileRequest{
		FullName: req.FullName,
		Phone:    &req.Phone,
	}

	// Вызываем сервис
	resp, err := s.AuthService.UpdateUserProfile(ctx, updateReq)
	if err != nil {
		s.Logger.Error("Failed to update user profile", zap.Error(err))
		return nil, status.Errorf(codes.Internal, locale.Get("profile_update_failed")+": %v", err)
	}

	// Конвертируем ответ в protobuf формат
	return &pb.UpdateUserProfileResponse{
		User: &pb.UserProfile{
			Id:               resp.User.ID,
			FullName:         resp.User.FullName,
			Email:            resp.User.Email,
			Phone:            resp.User.Phone,
			Role:             resp.User.Role,
			IsEmailVerified:  resp.User.IsEmailVerified,
			IsPhoneVerified:  resp.User.IsPhoneVerified,
			TwoFactorEnabled: resp.User.TwoFactorEnabled,
			Provider:         resp.User.Provider,
			LastLoginAt:      resp.User.LastLoginAt,
			CreatedAt:        resp.User.CreatedAt,
		},
		Message: resp.Message,
	}, nil
}

// ChangePassword реализует смену пароля
func (s *AuthServer) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*pb.ChangePasswordResponse, error) {
	s.Logger.Info("Change password request received")

	// Вызываем сервис
	resp, err := s.AuthService.ChangePassword(ctx, req.CurrentPassword, req.NewPassword, req.ConfirmPassword)
	if err != nil {
		s.Logger.Error("Failed to change password", zap.Error(err))
		return nil, status.Errorf(codes.Internal, locale.Get("password_change_failed")+": %v", err)
	}

	// Конвертируем ответ в protobuf формат
	return &pb.ChangePasswordResponse{
		Message: resp.Message,
		Success: resp.Success,
	}, nil
}

// ValidateToken реализует валидацию токена
func (s *AuthServer) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	s.Logger.Info("Validate token request received")

	// Вызываем сервис
	resp, err := s.AuthService.ValidateToken(ctx, req.AccessToken)
	if err != nil {
		s.Logger.Error("Token validation failed", zap.Error(err))
		return nil, status.Errorf(codes.Unauthenticated, locale.Get("token_invalid")+": %v", err)
	}

	// Конвертируем ответ в protobuf формат
	return &pb.ValidateTokenResponse{
		Valid: resp.Valid,
		User: &pb.UserProfile{
			Id:               resp.User.ID,
			FullName:         resp.User.FullName,
			Email:            resp.User.Email,
			Phone:            resp.User.Phone,
			Role:             resp.User.Role,
			IsEmailVerified:  resp.User.IsEmailVerified,
			IsPhoneVerified:  resp.User.IsPhoneVerified,
			TwoFactorEnabled: resp.User.TwoFactorEnabled,
			Provider:         resp.User.Provider,
			LastLoginAt:      resp.User.LastLoginAt,
			CreatedAt:        resp.User.CreatedAt,
		},
		Permissions: resp.Permissions,
	}, nil
}
