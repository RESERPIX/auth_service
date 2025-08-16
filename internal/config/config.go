package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Redis    RedisConfig    `mapstructure:"redis"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	Email    EmailConfig    `mapstructure:"email"`
	SMS      SMSConfig      `mapstructure:"sms"`
	OAuth    OAuthConfig    `mapstructure:"oauth"`
	Security SecurityConfig `mapstructure:"security"`
	Logging  LoggingConfig  `mapstructure:"logging"`
}

type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	Environment  string        `mapstructure:"environment"` // dev, prod, test
}

type DatabaseConfig struct {
	Host            string `mapstructure:"host"`
	Port            int    `mapstructure:"port"`
	User            string `mapstructure:"user"`
	Password        string `mapstructure:"password"`
	Name            string `mapstructure:"name"`
	SSLMode         string `mapstructure:"ssl_mode"`
	MaxOpenConns    int    `mapstructure:"max_open_conns"`
	MaxIdleConns    int    `mapstructure:"max_idle_conns"`
	ConnMaxLifetime string `mapstructure:"conn_max_lifetime"`
}

type RedisConfig struct {
	Addr         string `mapstructure:"addr"`
	Password     string `mapstructure:"password"`
	DB           int    `mapstructure:"db"`
	PoolSize     int    `mapstructure:"pool_size"`
	MinIdleConns int    `mapstructure:"min_idle_conns"`
}

type JWTConfig struct {
	AccessSecret     string        `mapstructure:"access_secret"`
	RefreshSecret    string        `mapstructure:"refresh_secret"`
	AccessTTL        time.Duration `mapstructure:"access_ttl"`
	RefreshTTL       time.Duration `mapstructure:"refresh_ttl"`
	TwoFactorTTL     time.Duration `mapstructure:"two_factor_ttl"`
	PasswordResetTTL time.Duration `mapstructure:"password_reset_ttl"`
}

type EmailConfig struct {
	SMTPHost     string `mapstructure:"smtp_host"`
	SMTPPort     int    `mapstructure:"smtp_port"`
	SMTPUser     string `mapstructure:"smtp_user"`
	SMTPPassword string `mapstructure:"smtp_password"`
	FromAddress  string `mapstructure:"from_address"`
	FromName     string `mapstructure:"from_name"`
}

type SMSConfig struct {
	Provider  string `mapstructure:"provider"` // sms_ru, twilio, etc.
	APIKey    string `mapstructure:"api_key"`
	APISecret string `mapstructure:"api_secret"`
	FromName  string `mapstructure:"from_name"`
}

type OAuthConfig struct {
	Yandex    OAuthProviderConfig `mapstructure:"yandex"`
	Mail      OAuthProviderConfig `mapstructure:"mail"`
	VK        OAuthProviderConfig `mapstructure:"vk"`
	Gosuslugi OAuthProviderConfig `mapstructure:"gosuslugi"`
}

type OAuthProviderConfig struct {
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	RedirectURL  string `mapstructure:"redirect_url"`
	Scopes       string `mapstructure:"scopes"`
}

type SecurityConfig struct {
	RecaptchaSecret    string        `mapstructure:"recaptcha_secret"`
	BCryptCost         int           `mapstructure:"bcrypt_cost"`
	MaxLoginAttempts   int           `mapstructure:"max_login_attempts"`
	LoginAttemptWindow time.Duration `mapstructure:"login_attempt_window"`
	CodeLength         int           `mapstructure:"code_length"`
	CodeTTL            time.Duration `mapstructure:"code_ttl"`
	MaxCodeAttempts    int           `mapstructure:"max_code_attempts"`
	RateLimitRequests  int           `mapstructure:"rate_limit_requests"`
	RateLimitWindow    time.Duration `mapstructure:"rate_limit_window"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"` // json, text
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath("./config")
	viper.AddConfigPath(".")

	// Настройка значений по умолчанию
	setDefaults()

	// Автоматическое связывание с переменными окружения
	viper.AutomaticEnv()

	// Чтение файла конфигурации
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

func setDefaults() {
	// Server defaults
	viper.SetDefault("server.host", "localhost")
	viper.SetDefault("server.port", 50051)
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.environment", "dev")

	// Database defaults
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.user", "postgres")
	viper.SetDefault("database.password", "postgres")
	viper.SetDefault("database.name", "auth_service")
	viper.SetDefault("database.ssl_mode", "disable")
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 5)
	viper.SetDefault("database.conn_max_lifetime", "1h")

	// Redis defaults
	viper.SetDefault("redis.addr", "localhost:6379")
	viper.SetDefault("redis.password", "")
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.pool_size", 10)
	viper.SetDefault("redis.min_idle_conns", 2)

	// JWT defaults
	viper.SetDefault("jwt.access_secret", "your-access-secret-key")
	viper.SetDefault("jwt.refresh_secret", "your-refresh-secret-key")
	viper.SetDefault("jwt.access_ttl", "15m")
	viper.SetDefault("jwt.refresh_ttl", "24h")
	viper.SetDefault("jwt.two_factor_ttl", "5m")
	viper.SetDefault("jwt.password_reset_ttl", "1h")

	// Security defaults
	viper.SetDefault("security.bcrypt_cost", 12)
	viper.SetDefault("security.max_login_attempts", 5)
	viper.SetDefault("security.login_attempt_window", "15m")
	viper.SetDefault("security.code_length", 6)
	viper.SetDefault("security.code_ttl", "5m")
	viper.SetDefault("security.max_code_attempts", 3)
	viper.SetDefault("security.rate_limit_requests", 100)
	viper.SetDefault("security.rate_limit_window", "1m")

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
}
