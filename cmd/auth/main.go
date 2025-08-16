// cmd/auth/main.go
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/RESERPIX/auth_service/internal/app"
	"github.com/RESERPIX/auth_service/internal/config"
	"github.com/RESERPIX/auth_service/internal/db"
	pb "github.com/RESERPIX/auth_service/internal/pb/proto/auth"
	"github.com/RESERPIX/auth_service/internal/services"
	"github.com/RESERPIX/auth_service/pkg/logger"

	"github.com/go-redis/redis/v9"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"gorm.io/gorm"
)

func main() {
	// Загрузка конфигурации
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Инициализация логгера
	zapLogger, err := logger.New(cfg.Logging.Level, cfg.Logging.Format)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer zapLogger.Sync()

	zapLogger.Info("Starting auth service", zap.String("environment", cfg.Server.Environment))

	// Подключение к PostgreSQL
	dbConn, err := connectDB(cfg)
	if err != nil {
		zapLogger.Fatal("Failed to connect to database", zap.Error(err))
	}

	// Миграции
	if err := runMigrations(dbConn); err != nil {
		zapLogger.Fatal("Failed to run migrations", zap.Error(err))
	}

	// Подключение к Redis
	redisClient := connectRedis(cfg)

	// Инициализация сервисов
	emailService := services.NewEmailService(cfg)
	smsService := services.NewSMSService(cfg)
	oauthService := services.NewOAuthService(cfg)
	authService := services.NewAuthService(dbConn, redisClient, cfg, emailService, smsService, oauthService)

	// Создание gRPC сервера
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(loggingInterceptor(zapLogger)),
	)

	// Регистрация сервисов
	authServer := &app.AuthServer{
		AuthService: authService,
		Logger:      zapLogger,
	}

	pb.RegisterAuthServiceServer(grpcServer, authServer)

	// Включение reflection для разработки
	if cfg.Server.Environment == "dev" {
		reflection.Register(grpcServer)
	}

	// Запуск сервера
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		zapLogger.Fatal("Failed to listen", zap.String("addr", addr), zap.Error(err))
	}

	zapLogger.Info("Auth service is running", zap.String("addr", addr))

	// Graceful shutdown
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			zapLogger.Fatal("Failed to serve", zap.Error(err))
		}
	}()

	// Ожидание сигналов для graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	zapLogger.Info("Shutting down server...")

	// Остановка gRPC сервера
	grpcServer.GracefulStop()

	// Закрытие соединений
	if sqlDB, err := dbConn.DB(); err == nil {
		sqlDB.Close()
	}
	redisClient.Close()

	zapLogger.Info("Server stopped")
}

func connectDB(cfg *config.Config) (*gorm.DB, error) {
	return db.ConnectPostgres(
		cfg.Database.Host,
		fmt.Sprintf("%d", cfg.Database.Port),
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Name,
	)
}

func connectRedis(cfg *config.Config) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:         cfg.Redis.Addr,
		Password:     cfg.Redis.Password,
		DB:           cfg.Redis.DB,
		PoolSize:     cfg.Redis.PoolSize,
		MinIdleConns: cfg.Redis.MinIdleConns,
	})
}

func runMigrations(dbConn *gorm.DB) error {
	return dbConn.AutoMigrate(
		&app.Role{},
		&app.User{},
		&app.VerificationCode{},
		&app.UserSession{},
		&app.UserAuditLog{},
	)
}

func loggingInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()
		
		resp, err := handler(ctx, req)
		
		duration := time.Since(start)
		
		if err != nil {
			logger.Error("gRPC request failed",
				zap.String("method", info.FullMethod),
				zap.Duration("duration", duration),
				zap.Error(err),
			)
		} else {
			logger.Info("gRPC request completed",
				zap.String("method", info.FullMethod),
				zap.Duration("duration", duration),
			)
		}
		
		return resp, err
	}
}

// internal/app/auth_server.go - обновленная версия
package app

import (
	"context"
	"errors"

	pb "github.com/RESERPIX/auth_service/internal/pb/proto/auth"
	"github.com/RESERPIX/auth_service/internal/services"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthServer struct {
	pb.UnimplementedAuthServiceServer
	AuthService *services.AuthService
	Logger      *zap.Logger
}

func (s *AuthServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	s.Logger.Info("Register request received", zap.String("email", req.Email))

	phone := ""
	if req.Phone != "" {
		phone = req.Phone
	}

	registerReq := services.RegisterRequest{
		FullName:        req.FullName,
		Email:           req.Email,
		Phone:           &phone,
		Password:        req.Password,
		ConfirmPassword: req.ConfirmPassword,
		AcceptTerms:     req.AcceptTerms,
		RecaptchaToken:  req.RecaptchaToken,
		ReferralCode:    req.ReferralCode,
	}

	resp, err := s.AuthService.Register(ctx, registerReq)
	if err != nil {
		s.Logger.Error("Registration failed", zap.Error(err))
		return nil, s.handleError(err)
	}

	return &pb.RegisterResponse{
		UserId:               resp.UserID,
		Message:              resp.Message,
		RequiresVerification: resp.RequiresVerification,
		VerificationType:     resp.VerificationType,
	}, nil
}

func (s *AuthServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	s.Logger.Info("Login request received", zap.String("login", req.Login))

	loginReq := services.LoginRequest{
		Login:          req.Login,
		Password:       req.Password,
		RecaptchaToken: req.RecaptchaToken,
		RememberMe:     req.RememberMe,
		DeviceID:       req.DeviceId,
		UserAgent:      req.UserAgent,
		IPAddress:      req.IpAddress,
	}

	resp, err := s.AuthService.Login(ctx, loginReq)
	if err != nil {
		s.Logger.Error("Login failed", zap.Error(err))
		return nil, s.handleError(err)
	}

	pbResp := &pb.LoginResponse{
		AccessToken:       resp.AccessToken,
		RefreshToken:      resp.RefreshToken,
		AccessExpiresIn:   resp.AccessExpiresIn,
		RefreshExpiresIn:  resp.RefreshExpiresIn,
		Requires_2Fa:      resp.Requires2FA,
		SessionId:         resp.SessionID,
	}

	if resp.User != nil {
		pbResp.User = &pb.UserProfile{
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
		}
	}

	return pbResp, nil
}

func (s *AuthServer) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	resp, err := s.AuthService.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		s.Logger.Error("Token refresh failed", zap.Error(err))
		return nil, s.handleError(err)
	}

return &pb.RefreshTokenResponse{
		AccessToken:       resp.AccessToken,
		RefreshToken:      resp.RefreshToken,
		AccessExpiresIn:   resp.AccessExpiresIn,
		RefreshExpiresIn:  resp.RefreshExpiresIn,
	}, nil
}

func (s *AuthServer) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	err := s.AuthService.Logout(ctx, req.RefreshToken, req.LogoutAllDevices)
	if err != nil {
		s.Logger.Error("Logout failed", zap.Error(err))
		return nil, s.handleError(err)
	}

	return &pb.LogoutResponse{
		Message: "Successfully logged out",
	}, nil
}

func (s *AuthServer) SendVerificationCode(ctx context.Context, req *pb.SendVerificationCodeRequest) (*pb.SendVerificationCodeResponse, error) {
	sendReq := services.SendVerificationCodeRequest{
		Contact: req.Contact,
		Type:    req.Type,
		Purpose: req.Purpose,
	}

	err := s.AuthService.SendVerificationCode(ctx, sendReq)
	if err != nil {
		s.Logger.Error("Send verification code failed", zap.Error(err))
		return nil, s.handleError(err)
	}

	return &pb.SendVerificationCodeResponse{
		Message:     "Verification code sent successfully",
		ExpiresIn:   300, // 5 минут
		RateLimited: false,
	}, nil
}

func (s *AuthServer) VerifyCode(ctx context.Context, req *pb.VerifyCodeRequest) (*pb.VerifyCodeResponse, error) {
	verifyReq := services.VerifyCodeRequest{
		Contact: req.Contact,
		Code:    req.Code,
		Type:    req.Type,
		Purpose: req.Purpose,
	}

	resp, err := s.AuthService.VerifyCode(ctx, verifyReq)
	if err != nil {
		s.Logger.Error("Code verification failed", zap.Error(err))
		return nil, s.handleError(err)
	}

	return &pb.VerifyCodeResponse{
		Success: resp.Success,
		Message: resp.Message,
		Token:   resp.Token,
	}, nil
}

func (s *AuthServer) RequestPasswordReset(ctx context.Context, req *pb.RequestPasswordResetRequest) (*pb.RequestPasswordResetResponse, error) {
	// Отправка кода верификации для сброса пароля
	sendReq := services.SendVerificationCodeRequest{
		Contact: req.Email,
		Type:    "email",
		Purpose: "password_reset",
	}

	err := s.AuthService.SendVerificationCode(ctx, sendReq)
	if err != nil {
		s.Logger.Error("Password reset request failed", zap.Error(err))
		return nil, s.handleError(err)
	}

	return &pb.RequestPasswordResetResponse{
		Message: "Password reset code sent to your email",
	}, nil
}

func (s *AuthServer) ResetPassword(ctx context.Context, req *pb.ResetPasswordRequest) (*pb.ResetPasswordResponse, error) {
	err := s.AuthService.ResetPassword(ctx, req.ResetToken, req.NewPassword, req.ConfirmPassword)
	if err != nil {
		s.Logger.Error("Password reset failed", zap.Error(err))
		return nil, s.handleError(err)
	}

	return &pb.ResetPasswordResponse{
		Message: "Password reset successfully",
		Success: true,
	}, nil
}

func (s *AuthServer) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	resp, err := s.AuthService.ValidateToken(ctx, req.AccessToken)
	if err != nil {
		return nil, s.handleError(err)
	}

	pbResp := &pb.ValidateTokenResponse{
		Valid:       resp.Valid,
		Permissions: resp.Permissions,
	}

	if resp.User != nil {
		pbResp.User = &pb.UserProfile{
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
		}
	}

	return pbResp, nil
}

// Обработка ошибок и преобразование в gRPC статусы
func (s *AuthServer) handleError(err error) error {
	switch {
	case errors.Is(err, services.ErrInvalidCredentials):
		return status.Error(codes.Unauthenticated, "Invalid credentials")
	case errors.Is(err, services.ErrUserNotFound):
		return status.Error(codes.NotFound, "User not found")
	case errors.Is(err, services.ErrUserExists):
		return status.Error(codes.AlreadyExists, "User already exists")
	case errors.Is(err, services.ErrInvalidCode):
		return status.Error(codes.InvalidArgument, "Invalid verification code")
	case errors.Is(err, services.ErrCodeExpired):
		return status.Error(codes.DeadlineExceeded, "Verification code expired")
	case errors.Is(err, services.ErrTooManyAttempts):
		return status.Error(codes.ResourceExhausted, "Too many attempts")
	case errors.Is(err, services.ErrInvalidToken):
		return status.Error(codes.Unauthenticated, "Invalid token")
	case errors.Is(err, services.ErrTokenExpired):
		return status.Error(codes.Unauthenticated, "Token expired")
	default:
		s.Logger.Error("Unhandled error", zap.Error(err))
		return status.Error(codes.Internal, "Internal server error")
	}
}