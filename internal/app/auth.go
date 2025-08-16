package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/RESERPIX/auth_service/pkg/utils"

	"gorm.io/gorm"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type AuthApp struct {
	DB        *gorm.DB
	JWTSecret string
	JWTTTL    time.Duration
}

func (a *AuthApp) Login(ctx context.Context, login, password string) (string, error) {
	login = strings.TrimSpace(login)

	var user User
	if err := a.DB.Preload("Role").
		Where("email = ? OR phone = ?", login, login).
		First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", ErrInvalidCredentials
		}
		return "", err
	}

	if !utils.CheckPassword(user.Password, password) {
		return "", ErrInvalidCredentials
	}

	roleName := user.Role.Name
	token, err := utils.GenerateJWT(user.ID, roleName, a.JWTSecret, a.JWTTTL)
	if err != nil {
		return "", err
	}
	return token, nil
}
