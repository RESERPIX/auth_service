package app

import (
	"time"

	"gorm.io/gorm"
)

type Role struct {
	ID        uint   `gorm:"primaryKey"`
	Name      string `gorm:"unique;not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
	Users     []User
}

type User struct {
	ID               uint    `gorm:"primaryKey"`
	FullName         string  `gorm:"not null"`
	Email            string  `gorm:"uniqueIndex;not null"`
	Phone            *string `gorm:"uniqueIndex"`
	Password         string  `gorm:"not null"`
	RoleID           uint    `gorm:"not null"`
	Role             Role    `gorm:"not null"`
	IsEmailVerified  bool    `gorm:"default:false"`
	IsPhoneVerified  bool    `gorm:"default:false"`
	EmailVerifiedAt  *time.Time
	PhoneVerifiedAt  *time.Time
	LastLoginAt      *time.Time
	TwoFactorEnabled bool `gorm:"default:false"`
	TwoFactorSecret  *string
	Provider         string `gorm:"default:'local'"` // local, yandex, mail, vk, gosuslugi
	ProviderID       *string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	DeletedAt        gorm.DeletedAt `gorm:"index"`
}

// Модель для хранения кодов верификации
type VerificationCode struct {
	ID        uint      `gorm:"primaryKey"`
	UserID    uint      `gorm:"not null"`
	User      User      `gorm:"foreignKey:UserID"`
	Code      string    `gorm:"not null"`
	Type      string    `gorm:"not null"` // email, sms, password_reset, 2fa
	ExpiresAt time.Time `gorm:"not null"`
	IsUsed    bool      `gorm:"default:false"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Модель для хранения сессий и токенов
type UserSession struct {
	ID           uint   `gorm:"primaryKey"`
	UserID       uint   `gorm:"not null"`
	User         User   `gorm:"foreignKey:UserID"`
	RefreshToken string `gorm:"not null;uniqueIndex"`
	UserAgent    string
	IPAddress    string
	ExpiresAt    time.Time `gorm:"not null"`
	IsActive     bool      `gorm:"default:true"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Модель для аудита действий пользователя
type UserAuditLog struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    *uint  // может быть nil для анонимных попыток
	User      *User  `gorm:"foreignKey:UserID"`
	Action    string `gorm:"not null"` // login, register, password_reset, etc.
	Details   string // JSON с деталями
	IPAddress string
	UserAgent string
	Success   bool `gorm:"default:true"`
	CreatedAt time.Time
}
