package locale

import "fmt"

// Messages содержит все сообщения на русском языке
var Messages = map[string]string{
	// Общие сообщения
	"success":                    "Успешно",
	"error":                      "Ошибка",
	"invalid_request":            "Неверный запрос",
	"internal_error":             "Внутренняя ошибка сервера",
	"service_unavailable":        "Сервис временно недоступен",
	
	// Аутентификация
	"login_successful":           "Вход выполнен успешно",
	"login_failed":               "Ошибка входа",
	"invalid_credentials":        "Неверный email/телефон или пароль",
	"user_not_found":             "Пользователь не найден",
	"account_locked":             "Аккаунт заблокирован",
	"too_many_attempts":          "Слишком много попыток входа. Попробуйте позже",
	
	// Регистрация
	"registration_successful":    "Регистрация выполнена успешно",
	"registration_failed":        "Ошибка регистрации",
	"user_already_exists":        "Пользователь уже существует",
	"email_already_exists":       "Пользователь с таким email уже существует",
	"phone_already_exists":       "Пользователь с таким телефоном уже существует",
	"password_mismatch":          "Пароли не совпадают",
	"terms_not_accepted":         "Необходимо принять условия использования",
	"weak_password":              "Пароль слишком слабый",
	
	// Верификация
	"verification_code_sent":     "Код подтверждения отправлен",
	"verification_successful":    "Подтверждение выполнено успешно",
	"verification_failed":        "Ошибка подтверждения",
	"invalid_code":               "Неверный код подтверждения",
	"code_expired":               "Код подтверждения истек",
	"too_many_code_attempts":    "Слишком много попыток ввода кода",
	
	// Восстановление пароля
	"password_reset_requested":   "Запрос на восстановление пароля отправлен",
	"password_reset_successful":  "Пароль успешно изменен",
	"password_reset_failed":      "Ошибка восстановления пароля",
	"reset_token_invalid":        "Неверный токен восстановления",
	"reset_token_expired":        "Токен восстановления истек",
	
	// Двухфакторная аутентификация
	"2fa_enabled":                "Двухфакторная аутентификация включена",
	"2fa_disabled":               "Двухфакторная аутентификация отключена",
	"2fa_required":               "Требуется двухфакторная аутентификация",
	"2fa_code_invalid":           "Неверный код 2FA",
	"backup_code_used":           "Использован резервный код",
	
	// OAuth
	"oauth_login_successful":     "Вход через %s выполнен успешно",
	"oauth_login_failed":         "Ошибка входа через %s",
	"oauth_provider_unsupported": "Неподдерживаемый OAuth провайдер",
	"oauth_code_invalid":         "Неверный OAuth код",
	
	// Валидация
	"email_invalid":              "Неверный формат email",
	"phone_invalid":              "Неверный формат номера телефона",
	"password_too_short":         "Пароль должен содержать минимум 8 символов",
	"password_too_long":          "Пароль должен содержать максимум 128 символов",
	"password_no_uppercase":      "Пароль должен содержать хотя бы одну заглавную букву",
	"password_no_lowercase":      "Пароль должен содержать хотя бы одну строчную букву",
	"password_no_number":         "Пароль должен содержать хотя бы одну цифру",
	"password_no_special":        "Пароль должен содержать хотя бы один специальный символ",
	"name_too_short":             "Имя должно содержать минимум 2 символа",
	"name_too_long":              "Имя должно содержать максимум 100 символов",
	
	// reCAPTCHA
	"recaptcha_required":         "Необходимо пройти проверку reCAPTCHA",
	"recaptcha_failed":           "Проверка reCAPTCHA не пройдена",
	
	// Rate limiting
	"rate_limit_exceeded":        "Превышен лимит запросов. Попробуйте позже",
	"too_many_requests":          "Слишком много запросов",
	
	// Сессии и токены
	"token_invalid":              "Неверный токен",
	"token_expired":              "Токен истек",
	"token_refreshed":            "Токен обновлен",
	"logout_successful":          "Выход выполнен успешно",
	"session_expired":            "Сессия истекла",
	
	// Профиль пользователя
	"profile_updated":            "Профиль обновлен",
	"profile_update_failed":      "Ошибка обновления профиля",
	"password_changed":           "Пароль изменен",
	"password_change_failed":     "Ошибка изменения пароля",
	
	// Email уведомления
	"welcome_message":            "Добро пожаловать, %s!",
	"verification_subject":       "Подтверждение регистрации",
	"password_reset_subject":     "Восстановление пароля",
	"2fa_enabled_subject":        "Двухфакторная аутентификация включена",
	
	// SMS уведомления
	"sms_verification_sent":      "SMS с кодом подтверждения отправлено",
	"sms_sending_failed":         "Ошибка отправки SMS",
	
	// Аудит
	"action_logged":              "Действие залогировано",
	"security_alert":             "Предупреждение безопасности",
	
	// Мониторинг
	"service_healthy":            "Сервис работает нормально",
	"service_unhealthy":          "Проблемы с сервисом",
	"database_connected":         "База данных подключена",
	"database_disconnected":      "База данных отключена",
	"redis_connected":            "Redis подключен",
	"redis_disconnected":         "Redis отключен",
}

// Get возвращает сообщение по ключу, или ключ если сообщение не найдено
func Get(key string) string {
	if msg, exists := Messages[key]; exists {
		return msg
	}
	return key
}

// Getf возвращает форматированное сообщение
func Getf(key string, args ...interface{}) string {
	msg := Get(key)
	return fmt.Sprintf(msg, args...)
}

// Has проверяет, существует ли сообщение для данного ключа
func Has(key string) bool {
	_, exists := Messages[key]
	return exists
}
