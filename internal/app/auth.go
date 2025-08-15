package app

import (
	"context"

	"github.com/RESERPIX/auth-service/pkg/utils"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AuthApp struct {
	DB *gorm.DB
}

func (a *AuthApp) Register(ctx context.Context, fullName, email, password string) (string, error) {
	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return "", err
	}

	user := User{
		ID:       0,
		FullName: fullName,
		Email:    email,
		Password: hashedPassword,
		RoleID:   2,
	}

	if err := a.DB.Create(&user).Error; err != nil {
		return "", err
	}

	return uuid.NewString(), nil

}
