package middleware

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// RateLimiterConfig конфигурация для rate limiter
type RateLimiterConfig struct {
	RequestsPerMinute int
	RequestsPerHour   int
	RequestsPerDay    int
	BurstSize         int
	WindowSize        time.Duration
}

// RateLimiter middleware для ограничения количества запросов
type RateLimiter struct {
	redis  *redis.Client
	config RateLimiterConfig
	logger *zap.Logger
}

// NewRateLimiter создает новый экземпляр RateLimiter
func NewRateLimiter(redis *redis.Client, config RateLimiterConfig, logger *zap.Logger) *RateLimiter {
	return &RateLimiter{
		redis:  redis,
		config: config,
		logger: logger,
	}
}

// UnaryServerInterceptor возвращает unary interceptor для rate limiting
func (rl *RateLimiter) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Получаем IP адрес из контекста
		clientIP := rl.extractClientIP(ctx)
		if clientIP == "" {
			clientIP = "unknown"
		}

		// Проверяем rate limit
		if err := rl.checkRateLimit(ctx, clientIP, info.FullMethod); err != nil {
			rl.logger.Warn("Rate limit exceeded",
				zap.String("client_ip", clientIP),
				zap.String("method", info.FullMethod),
				zap.Error(err),
			)
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded: %v", err)
		}

		// Увеличиваем счетчик запросов
		rl.incrementRequestCount(ctx, clientIP, info.FullMethod)

		// Выполняем запрос
		return handler(ctx, req)
	}
}

// extractClientIP извлекает IP адрес клиента из контекста
func (rl *RateLimiter) extractClientIP(ctx context.Context) string {
	// Пытаемся получить IP из metadata
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if xForwardedFor := md.Get("x-forwarded-for"); len(xForwardedFor) > 0 {
			return xForwardedFor[0]
		}
		if xRealIP := md.Get("x-real-ip"); len(xRealIP) > 0 {
			return xRealIP[0]
		}
	}

	// Если не удалось получить IP, возвращаем "unknown"
	return "unknown"
}

// checkRateLimit проверяет, не превышен ли лимит запросов
func (rl *RateLimiter) checkRateLimit(ctx context.Context, clientIP, method string) error {
	// Создаем ключи для разных временных окон
	minuteKey := fmt.Sprintf("rate_limit:%s:%s:minute", clientIP, method)
	hourKey := fmt.Sprintf("rate_limit:%s:%s:hour", clientIP, method)
	dayKey := fmt.Sprintf("rate_limit:%s:%s:day", clientIP, method)

	// Проверяем лимит в минуту
	if err := rl.checkWindowLimit(ctx, minuteKey, rl.config.RequestsPerMinute, time.Minute); err != nil {
		return fmt.Errorf("minute limit exceeded: %w", err)
	}

	// Проверяем лимит в час
	if err := rl.checkWindowLimit(ctx, hourKey, rl.config.RequestsPerHour, time.Hour); err != nil {
		return fmt.Errorf("hour limit exceeded: %w", err)
	}

	// Проверяем лимит в день
	if err := rl.checkWindowLimit(ctx, dayKey, rl.config.RequestsPerDay, 24*time.Hour); err != nil {
		return fmt.Errorf("day limit exceeded: %w", err)
	}

	return nil
}

// checkWindowLimit проверяет лимит для конкретного временного окна
func (rl *RateLimiter) checkWindowLimit(ctx context.Context, key string, limit int, window time.Duration) error {
	// Получаем текущий счетчик
	current, err := rl.redis.Get(ctx, key).Int()
	if err != nil && err != redis.Nil {
		rl.logger.Error("Failed to get rate limit counter", zap.Error(err))
		return err
	}

	// Если счетчик превышает лимит, возвращаем ошибку
	if current >= limit {
		return fmt.Errorf("limit %d exceeded", limit)
	}

	return nil
}

// incrementRequestCount увеличивает счетчик запросов
func (rl *RateLimiter) incrementRequestCount(ctx context.Context, clientIP, method string) {
	// Создаем ключи для разных временных окон
	minuteKey := fmt.Sprintf("rate_limit:%s:%s:minute", clientIP, method)
	hourKey := fmt.Sprintf("rate_limit:%s:%s:hour", clientIP, method)
	dayKey := fmt.Sprintf("rate_limit:%s:%s:day", clientIP, method)

	// Увеличиваем счетчики с TTL
	pipe := rl.redis.Pipeline()
	pipe.Incr(ctx, minuteKey)
	pipe.Expire(ctx, minuteKey, time.Minute)
	pipe.Incr(ctx, hourKey)
	pipe.Expire(ctx, hourKey, time.Hour)
	pipe.Incr(ctx, dayKey)
	pipe.Expire(ctx, dayKey, 24*time.Hour)

	if _, err := pipe.Exec(ctx); err != nil {
		rl.logger.Error("Failed to increment rate limit counters", zap.Error(err))
	}
}

// GetRateLimitInfo возвращает информацию о текущих лимитах для клиента
func (rl *RateLimiter) GetRateLimitInfo(ctx context.Context, clientIP, method string) (map[string]interface{}, error) {
	minuteKey := fmt.Sprintf("rate_limit:%s:%s:minute", clientIP, method)
	hourKey := fmt.Sprintf("rate_limit:%s:%s:hour", clientIP, method)
	dayKey := fmt.Sprintf("rate_limit:%s:%s:day", clientIP, method)

	pipe := rl.redis.Pipeline()
	minuteCmd := pipe.Get(ctx, minuteKey)
	hourCmd := pipe.Get(ctx, hourKey)
	dayCmd := pipe.Get(ctx, dayKey)

	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return nil, err
	}

	info := map[string]interface{}{
		"client_ip": clientIP,
		"method":    method,
		"limits": map[string]interface{}{
			"per_minute": rl.config.RequestsPerMinute,
			"per_hour":   rl.config.RequestsPerHour,
			"per_day":    rl.config.RequestsPerDay,
		},
		"current": map[string]interface{}{
			"per_minute": 0,
			"per_hour":   0,
			"per_day":    0,
		},
	}

	// Получаем текущие значения
	if minuteVal, err := minuteCmd.Int(); err == nil {
		info["current"].(map[string]interface{})["per_minute"] = minuteVal
	}
	if hourVal, err := hourCmd.Int(); err == nil {
		info["current"].(map[string]interface{})["per_hour"] = hourVal
	}
	if dayVal, err := dayCmd.Int(); err == nil {
		info["current"].(map[string]interface{})["per_day"] = dayVal
	}

	return info, nil
}

// ResetRateLimit сбрасывает счетчики для конкретного клиента
func (rl *RateLimiter) ResetRateLimit(ctx context.Context, clientIP, method string) error {
	minuteKey := fmt.Sprintf("rate_limit:%s:%s:minute", clientIP, method)
	hourKey := fmt.Sprintf("rate_limit:%s:%s:hour", clientIP, method)
	dayKey := fmt.Sprintf("rate_limit:%s:%s:day", clientIP, method)

	pipe := rl.redis.Pipeline()
	pipe.Del(ctx, minuteKey)
	pipe.Del(ctx, hourKey)
	pipe.Del(ctx, dayKey)

	_, err := pipe.Exec(ctx)
	return err
}
