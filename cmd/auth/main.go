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
	"github.com/RESERPIX/auth_service/internal/middleware"
	"github.com/RESERPIX/auth_service/internal/services"
	"github.com/RESERPIX/auth_service/pkg/logger"

	"github.com/redis/go-redis/v9"
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
	
	// Создание AuthService
	authService := services.NewAuthService(dbConn, redisClient, cfg, emailService, smsService, oauthService, zapLogger)

	// Создание middleware
	rateLimiter := middleware.NewRateLimiter(redisClient, middleware.RateLimiterConfig{
		RequestsPerMinute: cfg.Security.RateLimitPerMinute,
		RequestsPerHour:   cfg.Security.RateLimitPerHour,
		RequestsPerDay:    cfg.Security.RateLimitPerDay,
		WindowSize:        cfg.Security.RateLimitWindow,
	}, zapLogger)

	recaptchaMiddleware := middleware.NewRecaptchaMiddleware(middleware.RecaptchaConfig{
		SecretKey: cfg.Security.RecaptchaSecret,
		SiteKey:   cfg.Security.RecaptchaSiteKey,
		Enabled:   cfg.Security.RecaptchaEnabled,
		MinScore:  cfg.Security.RecaptchaMinScore,
	}, zapLogger)

	auditMiddleware := middleware.NewAuditMiddleware(middleware.AuditConfig{
		Enabled:      cfg.Middleware.AuditEnabled,
		LogToDB:     cfg.Middleware.AuditLogToDB,
		LogToConsole: cfg.Middleware.AuditLogToConsole,
		ExcludeMethods: cfg.Middleware.AuditExcludeMethods,
	}, zapLogger, dbConn)

	// Создание gRPC сервера с middleware
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			loggingInterceptor(zapLogger),
			rateLimiter.UnaryServerInterceptor(),
			recaptchaMiddleware.UnaryServerInterceptor(),
			auditMiddleware.UnaryServerInterceptor(),
		),
	)

	// Создание AuthServer
	authServer := app.NewAuthServer(authService, zapLogger)

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