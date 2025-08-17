package services

import (
	"testing"

	"github.com/RESERPIX/auth_service/pkg/utils"
	"github.com/stretchr/testify/assert"
)

// Простые unit тесты для функций валидации
func TestValidatePassword(t *testing.T) {
	// Тест валидного пароля
	t.Run("valid password", func(t *testing.T) {
		password := "SecurePass123!"
		errors := utils.ValidatePassword(password)
		assert.Empty(t, errors)
	})
	
	// Тест короткого пароля
	t.Run("short password", func(t *testing.T) {
		password := "Short1!"
		errors := utils.ValidatePassword(password)
		assert.Contains(t, errors, "Password must be at least 8 characters long")
	})
	
	// Тест пароля без заглавных букв
	t.Run("password without uppercase", func(t *testing.T) {
		password := "securepass123!"
		errors := utils.ValidatePassword(password)
		assert.Contains(t, errors, "Password must contain at least one uppercase letter")
	})
	
	// Тест пароля без строчных букв
	t.Run("password without lowercase", func(t *testing.T) {
		password := "SECUREPASS123!"
		errors := utils.ValidatePassword(password)
		assert.Contains(t, errors, "Password must contain at least one lowercase letter")
	})
	
	// Тест пароля без цифр
	t.Run("password without numbers", func(t *testing.T) {
		password := "SecurePass!"
		errors := utils.ValidatePassword(password)
		assert.Contains(t, errors, "Password must contain at least one number")
	})
	
	// Тест пароля без спецсимволов
	t.Run("password without special characters", func(t *testing.T) {
		password := "SecurePass123"
		errors := utils.ValidatePassword(password)
		assert.Contains(t, errors, "Password must contain at least one special character")
	})
}

func TestGenerateNumericCode(t *testing.T) {
	// Тест генерации кода
	t.Run("generate code", func(t *testing.T) {
		code, err := utils.GenerateNumericCode(6)
		assert.NoError(t, err)
		assert.Len(t, code, 6)
		assert.Regexp(t, `^\d{6}$`, code)
	})
	
	// Тест разной длины кода
	t.Run("different code lengths", func(t *testing.T) {
		code4, err := utils.GenerateNumericCode(4)
		assert.NoError(t, err)
		assert.Len(t, code4, 4)
		
		code8, err := utils.GenerateNumericCode(8)
		assert.NoError(t, err)
		assert.Len(t, code8, 8)
	})
	
	// Тест некорректной длины
	t.Run("invalid length", func(t *testing.T) {
		code, err := utils.GenerateNumericCode(0)
		assert.Error(t, err)
		assert.Empty(t, code)
		
		code, err = utils.GenerateNumericCode(-1)
		assert.Error(t, err)
		assert.Empty(t, code)
	})
}

func TestPasswordStrength(t *testing.T) {
	// Тест пустого пароля
	t.Run("empty password", func(t *testing.T) {
		strength := utils.PasswordStrength("")
		assert.Equal(t, 0, strength)
	})
	
	// Тест слабого пароля
	t.Run("weak password", func(t *testing.T) {
		strength := utils.PasswordStrength("password")
		assert.Equal(t, 2, strength) // длина + строчные
	})
	
	// Тест среднего пароля
	t.Run("medium password", func(t *testing.T) {
		strength := utils.PasswordStrength("Password123")
		assert.Equal(t, 4, strength) // длина + строчные + заглавные + цифры
	})
	
	// Тест сильного пароля
	t.Run("strong password", func(t *testing.T) {
		strength := utils.PasswordStrength("SecurePass123!")
		assert.Equal(t, 4, strength) // максимальный балл
	})
}

func TestIsValidEmail(t *testing.T) {
	// Тест валидных email
	validEmails := []string{
		"test@example.com",
		"user.name@domain.co.uk",
		"user+tag@example.org",
		"123@example.com",
	}
	
	for _, email := range validEmails {
		t.Run("valid email: "+email, func(t *testing.T) {
			assert.True(t, utils.IsValidEmail(email))
		})
	}
	
	// Тест невалидных email
	invalidEmails := []string{
		"invalid-email",
		"@example.com",
		"user@",
		"",
	}
	
	for _, email := range invalidEmails {
		t.Run("invalid email: "+email, func(t *testing.T) {
			assert.False(t, utils.IsValidEmail(email))
		})
	}
}

func TestIsValidPhone(t *testing.T) {
	// Тест валидных номеров телефонов
	validPhones := []string{
		"+79001234567",
		"89001234567",
		"+7 (900) 123-45-67",
		"8-900-123-45-67",
		"+1-555-123-4567",
	}
	
	for _, phone := range validPhones {
		t.Run("valid phone: "+phone, func(t *testing.T) {
			assert.True(t, utils.IsValidPhone(phone))
		})
	}
	
	// Тест невалидных номеров телефонов
	invalidPhones := []string{
		"not-a-phone",
		"",
		"+",
	}
	
	for _, phone := range invalidPhones {
		t.Run("invalid phone: "+phone, func(t *testing.T) {
			assert.False(t, utils.IsValidPhone(phone))
		})
	}
}

func TestIsValidFullName(t *testing.T) {
	// Тест валидных имен
	validNames := []string{
		"John Doe",
		"Иван Иванов",
		"Jean-Pierre",
		"O'Connor",
		"Mary Jane Watson",
	}
	
	for _, name := range validNames {
		t.Run("valid name: "+name, func(t *testing.T) {
			assert.True(t, utils.IsValidFullName(name))
		})
	}
	
	// Тест невалидных имен
	invalidNames := []string{
		"A",           // слишком короткое
		"",            // пустое
		"John123",     // содержит цифры
		"John@Doe",    // содержит спецсимволы
	}
	
	for _, name := range invalidNames {
		t.Run("invalid name: "+name, func(t *testing.T) {
			assert.False(t, utils.IsValidFullName(name))
		})
	}
}
