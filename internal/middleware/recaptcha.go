package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// RecaptchaConfig конфигурация для reCAPTCHA
type RecaptchaConfig struct {
	SecretKey string
	SiteKey   string
	Enabled   bool
	MinScore  float64 // для reCAPTCHA v3
}

// RecaptchaResponse ответ от Google reCAPTCHA API
type RecaptchaResponse struct {
	Success     bool    `json:"success"`
	Score       float64 `json:"score"`
	Action      string  `json:"action"`
	ChallengeTs string  `json:"challenge_ts"`
	Hostname    string  `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
}

// RecaptchaMiddleware middleware для проверки reCAPTCHA
type RecaptchaMiddleware struct {
	config RecaptchaConfig
	logger *zap.Logger
	client *http.Client
}

// NewRecaptchaMiddleware создает новый экземпляр RecaptchaMiddleware
func NewRecaptchaMiddleware(config RecaptchaConfig, logger *zap.Logger) *RecaptchaMiddleware {
	return &RecaptchaMiddleware{
		config: config,
		logger: logger,
		client: &http.Client{},
	}
}

// UnaryServerInterceptor возвращает unary interceptor для проверки reCAPTCHA
func (rm *RecaptchaMiddleware) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Если reCAPTCHA отключена, пропускаем проверку
		if !rm.config.Enabled {
			return handler(ctx, req)
		}

		// Проверяем, требуется ли проверка reCAPTCHA для данного метода
		if rm.requiresRecaptcha(info.FullMethod) {
			// Извлекаем токен reCAPTCHA из metadata
			token := rm.extractRecaptchaToken(ctx)
			if token == "" {
				return nil, status.Errorf(codes.InvalidArgument, "reCAPTCHA token is required")
			}

			// Проверяем токен
			if err := rm.verifyRecaptcha(ctx, token); err != nil {
				rm.logger.Warn("reCAPTCHA verification failed",
					zap.String("method", info.FullMethod),
					zap.Error(err),
				)
				return nil, status.Errorf(codes.PermissionDenied, "reCAPTCHA verification failed: %v", err)
			}
		}

		// Выполняем запрос
		return handler(ctx, req)
	}
}

// requiresRecaptcha проверяет, требуется ли reCAPTCHA для данного метода
func (rm *RecaptchaMiddleware) requiresRecaptcha(method string) bool {
	// Методы, которые требуют проверки reCAPTCHA
	protectedMethods := []string{
		"/auth.AuthService/Register",
		"/auth.AuthService/Login",
		"/auth.AuthService/RequestPasswordReset",
		"/auth.AuthService/SendVerificationCode",
	}

	for _, protected := range protectedMethods {
		if strings.Contains(method, protected) {
			return true
		}
	}

	return false
}

// extractRecaptchaToken извлекает токен reCAPTCHA из metadata
func (rm *RecaptchaMiddleware) extractRecaptchaToken(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if tokens := md.Get("x-recaptcha-token"); len(tokens) > 0 {
			return tokens[0]
		}
		if tokens := md.Get("recaptcha-token"); len(tokens) > 0 {
			return tokens[0]
		}
	}
	return ""
}

// verifyRecaptcha проверяет токен reCAPTCHA через Google API
func (rm *RecaptchaMiddleware) verifyRecaptcha(ctx context.Context, token string) error {
	// Формируем запрос к Google reCAPTCHA API
	data := url.Values{}
	data.Set("secret", rm.config.SecretKey)
	data.Set("response", token)

	// Отправляем POST запрос
	resp, err := rm.client.PostForm("https://www.google.com/recaptcha/api/siteverify", data)
	if err != nil {
		return fmt.Errorf("failed to verify reCAPTCHA: %w", err)
	}
	defer resp.Body.Close()

	// Читаем ответ
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read reCAPTCHA response: %w", err)
	}

	// Парсим JSON ответ
	var recaptchaResp RecaptchaResponse
	if err := json.Unmarshal(body, &recaptchaResp); err != nil {
		return fmt.Errorf("failed to parse reCAPTCHA response: %w", err)
	}

	// Проверяем успешность
	if !recaptchaResp.Success {
		errorCodes := strings.Join(recaptchaResp.ErrorCodes, ", ")
		return fmt.Errorf("reCAPTCHA verification failed: %s", errorCodes)
	}

	// Для reCAPTCHA v3 проверяем score
	if rm.config.MinScore > 0 && recaptchaResp.Score < rm.config.MinScore {
		return fmt.Errorf("reCAPTCHA score too low: %f (minimum: %f)", recaptchaResp.Score, rm.config.MinScore)
	}

	return nil
}

// VerifyRecaptchaToken проверяет токен reCAPTCHA (для использования в сервисах)
func (rm *RecaptchaMiddleware) VerifyRecaptchaToken(ctx context.Context, token string) error {
	if !rm.config.Enabled {
		return nil
	}

	if token == "" {
		return fmt.Errorf("reCAPTCHA token is required")
	}

	return rm.verifyRecaptcha(ctx, token)
}

// GetRecaptchaSiteKey возвращает публичный ключ для frontend
func (rm *RecaptchaMiddleware) GetRecaptchaSiteKey() string {
	return rm.config.SiteKey
}

// IsEnabled возвращает, включена ли проверка reCAPTCHA
func (rm *RecaptchaMiddleware) IsEnabled() bool {
	return rm.config.Enabled
}
