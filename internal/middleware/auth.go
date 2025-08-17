package middleware

import (
	"context"
	"fmt"
	"strings"

	"github.com/RESERPIX/auth_service/internal/app"
	"github.com/RESERPIX/auth_service/pkg/utils"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

// AuthConfig конфигурация для аутентификации
type AuthConfig struct {
	JWTSecret string
	Enabled   bool
}

// AuthMiddleware middleware для аутентификации пользователей
type AuthMiddleware struct {
	config AuthConfig
	logger *zap.Logger
	db     *gorm.DB
}

// NewAuthMiddleware создает новый экземпляр AuthMiddleware
func NewAuthMiddleware(config AuthConfig, logger *zap.Logger, db *gorm.DB) *AuthMiddleware {
	return &AuthMiddleware{
		config: config,
		logger: logger,
		db:     db,
	}
}

// UnaryServerInterceptor возвращает unary interceptor для аутентификации
func (am *AuthMiddleware) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Если аутентификация отключена, пропускаем проверку
		if !am.config.Enabled {
			return handler(ctx, req)
		}

		// Проверяем, требуется ли аутентификация для данного метода
		if am.requiresAuth(info.FullMethod) {
			// Извлекаем токен из metadata
			token, err := am.extractToken(ctx)
			if err != nil {
				return nil, status.Errorf(codes.Unauthenticated, "authentication required: %v", err)
			}

			// Проверяем токен
			claims, err := am.validateToken(token)
			if err != nil {
				return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
			}

			// Проверяем, что пользователь существует
			user, err := am.getUserByID(claims.UserID)
			if err != nil {
				return nil, status.Errorf(codes.Unauthenticated, "user not found")
			}

			// Добавляем информацию о пользователе в контекст
			ctx = am.addUserToContext(ctx, user, claims)
		}

		// Выполняем запрос
		return handler(ctx, req)
	}
}

// requiresAuth проверяет, требуется ли аутентификация для данного метода
func (am *AuthMiddleware) requiresAuth(method string) bool {
	// Методы, которые НЕ требуют аутентификации
	publicMethods := []string{
		"/auth.AuthService/Register",
		"/auth.AuthService/Login",
		"/auth.AuthService/RefreshToken",
		"/auth.AuthService/VerifyCode",
		"/auth.AuthService/SendVerificationCode",
		"/auth.AuthService/RequestPasswordReset",
		"/auth.AuthService/ResetPassword",
		"/auth.AuthService/LoginWithProvider",
	}

	for _, public := range publicMethods {
		if method == public {
			return false
		}
	}

	// Все остальные методы требуют аутентификации
	return true
}

// extractToken извлекает токен из metadata
func (am *AuthMiddleware) extractToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", fmt.Errorf("no metadata found in context")
	}

	// Ищем токен в заголовках Authorization
	if authHeaders := md.Get("authorization"); len(authHeaders) > 0 {
		authHeader := authHeaders[0]
		if strings.HasPrefix(authHeader, "Bearer ") {
			return strings.TrimPrefix(authHeader, "Bearer "), nil
		}
	}

	// Ищем токен в заголовках access_token
	if tokenHeaders := md.Get("access_token"); len(tokenHeaders) > 0 {
		return tokenHeaders[0], nil
	}

	return "", fmt.Errorf("no valid token found")
}

// validateToken проверяет токен JWT
func (am *AuthMiddleware) validateToken(token string) (*utils.Claims, error) {
	claims, err := utils.ValidateJWT(token, am.config.JWTSecret)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	return claims, nil
}

// getUserByID получает пользователя по ID
func (am *AuthMiddleware) getUserByID(userID uint) (*app.User, error) {
	var user app.User
	err := am.db.Preload("Role").First(&user, userID).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// addUserToContext добавляет информацию о пользователе в контекст
func (am *AuthMiddleware) addUserToContext(ctx context.Context, user *app.User, claims *utils.Claims) context.Context {
	// Создаем новый контекст с информацией о пользователе
	ctx = context.WithValue(ctx, "user_id", user.ID)
	ctx = context.WithValue(ctx, "user_role", user.Role.Name)
	ctx = context.WithValue(ctx, "user_email", user.Email)
	
	return ctx
}

// GetUserFromContext извлекает информацию о пользователе из контекста
func GetUserFromContext(ctx context.Context) (uint, string, string, error) {
	userID, ok := ctx.Value("user_id").(uint)
	if !ok {
		return 0, "", "", fmt.Errorf("user ID not found in context")
	}

	userRole, ok := ctx.Value("user_role").(string)
	if !ok {
		return 0, "", "", fmt.Errorf("user role not found in context")
	}

	userEmail, ok := ctx.Value("user_email").(string)
	if !ok {
		return 0, "", "", fmt.Errorf("user email not found in context")
	}

	return userID, userRole, userEmail, nil
}