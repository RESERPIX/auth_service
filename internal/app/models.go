package app

import "time"

type Role struct {
	ID        uint   `gorm:"PrimaryKey"`
	Name      string `gorm:"unique;not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
	Users     []User
}

type User struct {
	ID        uint    `gorm:"primaryKey"`
	FullName  string  `gorm:"not null"`
	Email     string  `gorm:"uniqueIndex;not null"`
	Phone     *string `gorm:"uniqueIndex"`
	Password  string  `gorm:"not null"`
	RoleID    uint    `gorm:"not null"`
	Role      Role    `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}
