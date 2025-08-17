package services

import (
	"context"
	"time"
)

// EmailServiceInterface определяет интерфейс для email сервиса
type EmailServiceInterface interface {
	SendVerificationCode(email, code, purpose string) error
	SendWelcomeEmail(email, fullName string) error
	SendPasswordResetEmail(email, resetLink string) error
}

// SMSServiceInterface определяет интерфейс для SMS сервиса
type SMSServiceInterface interface {
	SendVerificationCode(phone, code, purpose string) error
}

// OAuthServiceInterface определяет интерфейс для OAuth сервиса
type OAuthServiceInterface interface {
	GetAuthURL(provider, state, redirectURI string) (string, error)
	ExchangeCodeForUserInfo(ctx context.Context, provider, code, state, redirectURI string) (*OAuthUserInfo, error)
}

// DatabaseInterface определяет интерфейс для работы с базой данных
type DatabaseInterface interface {
	Create(value interface{}) DatabaseInterface
	Where(query interface{}, args ...interface{}) DatabaseInterface
	First(dest interface{}, conds ...interface{}) DatabaseInterface
	Preload(query string, args ...interface{}) DatabaseInterface
	Save(value interface{}) DatabaseInterface
	Error() error
}

// RedisInterface определяет интерфейс для работы с Redis
type RedisInterface interface {
	Get(ctx context.Context, key string) RedisStringCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) RedisStatusCmd
	Del(ctx context.Context, keys ...string) RedisIntCmd
	Close() error
}

// RedisStringCmd интерфейс для Redis команды String
type RedisStringCmd interface {
	Result() (string, error)
	Int64() (int64, error)
	Val() string
}

// RedisStatusCmd интерфейс для Redis команды Status
type RedisStatusCmd interface {
	Result() (string, error)
	Err() error
}

// RedisIntCmd интерфейс для Redis команды Int
type RedisIntCmd interface {
	Result() (int64, error)
	Err() error
}
