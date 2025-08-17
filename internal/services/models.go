package services

import (
	"time"
)

// User модель пользователя для сервисов
type User struct {
	ID               uint      `json:"id"`
	FullName         string    `json:"full_name"`
	Email            string    `json:"email"`
	Phone            *string   `json:"phone"`
	Password         string    `json:"-"`
	RoleID           uint      `json:"role_id"`
	Role             Role      `json:"role"`
	IsEmailVerified  bool      `json:"is_email_verified"`
	IsPhoneVerified  bool      `json:"is_phone_verified"`
	EmailVerifiedAt  *time.Time `json:"email_verified_at"`
	PhoneVerifiedAt  *time.Time `json:"phone_verified_at"`
	LastLoginAt      *time.Time `json:"last_login_at"`
	TwoFactorEnabled bool      `json:"two_factor_enabled"`
	TwoFactorSecret  *string   `json:"-"`
	Provider         string    `json:"provider"`
	ProviderID       *string   `json:"provider_id"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// Role модель роли для сервисов
type Role struct {
	ID        uint   `json:"id"`
	Name      string `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// VerificationCode модель кода верификации для сервисов
type VerificationCode struct {
	ID        uint      `json:"id"`
	UserID    uint      `json:"user_id"`
	User      User      `json:"user"`
	Code      string    `json:"code"`
	Type      string    `json:"type"`
	Purpose   string    `json:"purpose"`
	ExpiresAt time.Time `json:"expires_at"`
	IsUsed    bool      `json:"is_used"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UserSession модель сессии пользователя для сервисов
type UserSession struct {
	ID           uint      `json:"id"`
	UserID       uint      `json:"user_id"`
	User         User      `json:"user"`
	RefreshToken string    `json:"refresh_token"`
	UserAgent    string    `json:"user_agent"`
	IPAddress    string    `json:"ip_address"`
	ExpiresAt    time.Time `json:"expires_at"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// UserAuditLog модель аудита для сервисов
type UserAuditLog struct {
	ID        uint      `json:"id"`
	UserID    *uint     `json:"user_id"`
	User      *User     `json:"user"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	Success   bool      `json:"success"`
	CreatedAt time.Time `json:"created_at"`
}
