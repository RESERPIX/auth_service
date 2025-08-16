// pkg/utils/jwt.go - расширенная версия
package utils

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID uint   `json:"uid"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrTokenExpired = errors.New("token expired")
)

func GenerateJWT(userID uint, role, secret string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "auth_service",
			Subject:   string(rune(userID)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func ValidateJWT(tokenString, secret string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

func ExtractUserIDFromToken(tokenString, secret string) (uint, error) {
	claims, err := ValidateJWT(tokenString, secret)
	if err != nil {
		return 0, err
	}
	return claims.UserID, nil
}

// pkg/utils/validation.go
package utils

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	phoneRegex = regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
)

// Валидация email
func IsValidEmail(email string) bool {
	email = strings.TrimSpace(strings.ToLower(email))
	return len(email) > 0 && len(email) <= 254 && emailRegex.MatchString(email)
}

// Валидация номера телефона
func IsValidPhone(phone string) bool {
	// Удаляем пробелы и спецсимволы
	cleaned := strings.ReplaceAll(phone, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, "(", "")
	cleaned = strings.ReplaceAll(cleaned, ")", "")
	
	return phoneRegex.MatchString(cleaned)
}

// Валидация пароля
func ValidatePassword(password string) []string {
	var errors []string
	
	if len(password) < 8 {
		errors = append(errors, "Password must be at least 8 characters long")
	}
	
	if len(password) > 128 {
		errors = append(errors, "Password must be less than 128 characters")
	}
	
	var (
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)
	
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	
	if !hasUpper {
		errors = append(errors, "Password must contain at least one uppercase letter")
	}
	
	if !hasLower {
		errors = append(errors, "Password must contain at least one lowercase letter")
	}
	
	if !hasNumber {
		errors = append(errors, "Password must contain at least one number")
	}
	
	if !hasSpecial {
		errors = append(errors, "Password must contain at least one special character")
	}
	
	return errors
}

// Проверка силы пароля (0-4)
func PasswordStrength(password string) int {
	if len(password) == 0 {
		return 0
	}
	
	score := 0
	
	// Длина
	if len(password) >= 8 {
		score++
	}
	
	// Типы символов
	var (
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)
	
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	
	if hasLower {
		score++
	}
	if hasUpper {
		score++
	}
	if hasNumber {
		score++
	}
	if hasSpecial {
		score++
	}
	
	// Дополнительные очки за длину
	if len(password) >= 12 {
		score++
	}
	
	if score > 4 {
		score = 4
	}
	
	return score
}

// Валидация полного имени
func IsValidFullName(name string) bool {
	name = strings.TrimSpace(name)
	if len(name) < 2 || len(name) > 100 {
		return false
	}
	
	// Проверяем, что содержит только буквы, пробелы и дефисы
	for _, char := range name {
		if !unicode.IsLetter(char) && char != ' ' && char != '-' && char != '\'' {
			return false
		}
	}
	
	return true
}

// pkg/utils/security.go
package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Генерация случайной строки
func GenerateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		b[i] = charset[num.Int64()]
	}
	
	return string(b), nil
}

// Генерация числового кода
func GenerateNumericCode(length int) (string, error) {
	max := big.NewInt(int64(1))
	for i := 0; i < length; i++ {
		max.Mul(max, big.NewInt(10))
	}
	
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	
	return fmt.Sprintf("%0*d", length, n.Int64()), nil
}

// Генерация безопасного токена
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// Безопасное сравнение строк (защита от timing attacks)
func SecureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Маскировка email для логов
func MaskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "***@***"
	}
	
	username := parts[0]
	domain := parts[1]
	
	if len(username) <= 2 {
		return "***@" + domain
	}
	
	masked := username[:1] + strings.Repeat("*", len(username)-2) + username[len(username)-1:]
	return masked + "@" + domain
}

// Маскировка номера телефона для логов
func MaskPhone(phone string) string {
	if len(phone) <= 4 {
		return "***"
	}
	
	return phone[:2] + strings.Repeat("*", len(phone)-4) + phone[len(phone)-2:]
}

// pkg/utils/rate_limit.go
package utils

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v9"
)

type RateLimiter struct {
	client *redis.Client
}

func NewRateLimiter(client *redis.Client) *RateLimiter {
	return &RateLimiter{client: client}
}

// Проверка лимита запросов
func (r *RateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	pipe := r.client.TxPipeline()
	
	// Увеличиваем счетчик
	incr := pipe.Incr(ctx, key)
	// Устанавливаем TTL только если это первый запрос
	pipe.Expire(ctx, key, window)
	
	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, err
	}
	
	count := incr.Val()
	return count <= int64(limit), nil
}

// Получение текущего количества запросов
func (r *RateLimiter) GetCount(ctx context.Context, key string) (int64, error) {
	return r.client.Get(ctx, key).Int64()
}

// Очистка лимита
func (r *RateLimiter) Reset(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

// Создание ключа для rate limiting
func (r *RateLimiter) CreateKey(prefix, identifier string) string {
	return fmt.Sprintf("rate_limit:%s:%s", prefix, identifier)
}

// pkg/logger/logger.go
package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func New(level, format string) (*zap.Logger, error) {
	var config zap.Config
	
	switch format {
	case "json":
		config = zap.NewProductionConfig()
	default:
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}
	
	// Установка уровня логирования
	switch level {
	case "debug":
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		config.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		config.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	
	return config.Build()
}

// Структурированное логирование для аудита
func AuditLog(logger *zap.Logger, userID uint, action, resource, result string, metadata map[string]interface{}) {
	fields := []zap.Field{
		zap.Uint("user_id", userID),
		zap.String("action", action),
		zap.String("resource", resource),
		zap.String("result", result),
		zap.Time("timestamp", time.Now()),
	}
	
	for k, v := range metadata {
		fields = append(fields, zap.Any(k, v))
	}
	
	logger.Info("audit_log", fields...)
}