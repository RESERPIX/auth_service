// internal/services/email_service.go
package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"

	"github.com/RESERPIX/auth_service/internal/config"
)

type EmailService struct {
	config *config.Config
}

func NewEmailService(config *config.Config) *EmailService {
	return &EmailService{config: config}
}

func (s *EmailService) SendVerificationCode(email, code, purpose string) error {
	subject := s.getSubjectByPurpose(purpose)
	body := s.getBodyByPurpose(purpose, code)

	return s.sendEmail(email, subject, body)
}

func (s *EmailService) SendWelcomeEmail(email, fullName string) error {
	subject := "Добро пожаловать!"

	tmpl := `
	<!DOCTYPE html>
	<html>
	<head>
		<meta charset="UTF-8">
		<title>Добро пожаловать</title>
	</head>
	<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
		<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
			<h2 style="color: #2c5aa0;">Добро пожаловать, {{.FullName}}!</h2>
			<p>Спасибо за регистрацию на нашей платформе.</p>
			<p>Ваш аккаунт был успешно создан и верифицирован.</p>
			<p>Теперь вы можете воспользоваться всеми возможностями нашего сервиса.</p>
			
			<div style="margin: 30px 0; padding: 20px; background-color: #f8f9fa; border-radius: 5px;">
				<h3 style="margin-top: 0;">Что дальше?</h3>
				<ul>
					<li>Заполните профиль для персонализации</li>
					<li>Настройте уведомления</li>
					<li>Изучите возможности платформы</li>
				</ul>
			</div>
			
			<p style="margin-top: 30px;">
				С уважением,<br>
				Команда поддержки
			</p>
		</div>
	</body>
	</html>
	`

	t, err := template.New("welcome").Parse(tmpl)
	if err != nil {
		return err
	}

	var body bytes.Buffer
	err = t.Execute(&body, struct {
		FullName string
	}{
		FullName: fullName,
	})
	if err != nil {
		return err
	}

	return s.sendEmail(email, subject, body.String())
}

func (s *EmailService) SendPasswordResetEmail(email, resetLink string) error {
	subject := "Восстановление пароля"

	tmpl := `
	<!DOCTYPE html>
	<html>
	<head>
		<meta charset="UTF-8">
		<title>Восстановление пароля</title>
	</head>
	<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
		<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
			<h2 style="color: #2c5aa0;">Восстановление пароля</h2>
			<p>Вы запросили восстановление пароля для вашего аккаунта.</p>
			<p>Для продолжения процедуры восстановления перейдите по ссылке:</p>
			
			<div style="margin: 30px 0; text-align: center;">
				<a href="{{.ResetLink}}" 
				   style="background-color: #007bff; color: white; padding: 12px 30px; 
				          text-decoration: none; border-radius: 5px; display: inline-block;">
					Восстановить пароль
				</a>
			</div>
			
			<p style="color: #666; font-size: 14px;">
				Если вы не запрашивали восстановление пароля, просто проигнорируйте это письмо.
			</p>
			
			<p style="color: #666; font-size: 14px;">
				Ссылка действительна в течение 1 часа.
			</p>
			
			<p style="margin-top: 30px;">
				С уважением,<br>
				Команда поддержки
			</p>
		</div>
	</body>
	</html>
	`

	t, err := template.New("password_reset").Parse(tmpl)
	if err != nil {
		return err
	}

	var body bytes.Buffer
	err = t.Execute(&body, struct {
		ResetLink string
	}{
		ResetLink: resetLink,
	})
	if err != nil {
		return err
	}

	return s.sendEmail(email, subject, body.String())
}

func (s *EmailService) getSubjectByPurpose(purpose string) string {
	switch purpose {
	case "registration":
		return "Подтверждение регистрации"
	case "password_reset":
		return "Код для восстановления пароля"
	case "2fa":
		return "Код двухфакторной аутентификации"
	default:
		return "Код подтверждения"
	}
}

func (s *EmailService) getBodyByPurpose(purpose, code string) string {
	templates := map[string]string{
		"registration": `
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="UTF-8">
			<title>Подтверждение регистрации</title>
		</head>
		<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
			<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
				<h2 style="color: #2c5aa0;">Подтверждение регистрации</h2>
				<p>Спасибо за регистрацию! Для завершения регистрации введите код:</p>
				
				<div style="margin: 30px 0; text-align: center;">
					<div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; 
					            font-size: 32px; font-weight: bold; letter-spacing: 5px; 
					            color: #2c5aa0; border: 2px dashed #2c5aa0;">
						%s
					</div>
				</div>
				
				<p style="color: #666; font-size: 14px;">
					Код действителен в течение 5 минут.
				</p>
				
				<p style="margin-top: 30px;">
					С уважением,<br>
					Команда поддержки
				</p>
			</div>
		</body>
		</html>
		`,

		"password_reset": `
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="UTF-8">
			<title>Восстановление пароля</title>
		</head>
		<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
			<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
				<h2 style="color: #dc3545;">Восстановление пароля</h2>
				<p>Вы запросили восстановление пароля. Введите код для подтверждения:</p>
				
				<div style="margin: 30px 0; text-align: center;">
					<div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; 
					            font-size: 32px; font-weight: bold; letter-spacing: 5px; 
					            color: #dc3545; border: 2px dashed #dc3545;">
						%s
					</div>
				</div>
				
				<p style="color: #666; font-size: 14px;">
					Если вы не запрашивали восстановление пароля, просто проигнорируйте это письмо.
				</p>
				
				<p style="margin-top: 30px;">
					С уважением,<br>
					Команда поддержки
				</p>
			</div>
		</body>
		</html>
		`,

		"2fa": `
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="UTF-8">
			<title>Код двухфакторной аутентификации</title>
		</head>
		<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
			<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
				<h2 style="color: #28a745;">Двухфакторная аутентификация</h2>
				<p>Ваш код для входа в систему:</p>
				
				<div style="margin: 30px 0; text-align: center;">
					<div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; 
					            font-size: 32px; font-weight: bold; letter-spacing: 5px; 
					            color: #28a745; border: 2px dashed #28a745;">
						%s
					</div>
				</div>
				
				<p style="color: #666; font-size: 14px;">
					Код действителен в течение 5 минут.
				</p>
				
				<p style="margin-top: 30px;">
					С уважением,<br>
					Команда поддержки
				</p>
			</div>
		</body>
		</html>
		`,
	}

	template := templates[purpose]
	if template == "" {
		template = templates["registration"]
	}

	return fmt.Sprintf(template, code)
}

func (s *EmailService) sendEmail(to, subject, body string) error {
	from := s.config.Email.FromAddress
	password := s.config.Email.SMTPPassword

	// Настройка SMTP
	auth := smtp.PlainAuth("", s.config.Email.SMTPUser, password, s.config.Email.SMTPHost)

	// Формирование сообщения
	msg := []byte("To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-version: 1.0;\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\";\r\n" +
		"\r\n" + body)

	// Отправка
	addr := fmt.Sprintf("%s:%d", s.config.Email.SMTPHost, s.config.Email.SMTPPort)
	return smtp.SendMail(addr, auth, from, []string{to}, msg)
}

// internal/services/sms_service.go

type SMSService struct {
	config *config.Config
	client *resty.Client
}

func NewSMSService(config *config.Config) *SMSService {
	return &SMSService{
		config: config,
		client: resty.New(),
	}
}

func (s *SMSService) SendVerificationCode(phone, code, purpose string) error {
	message := s.getMessageByPurpose(purpose, code)

	switch s.config.SMS.Provider {
	case "sms_ru":
		return s.sendSMSRu(phone, message)
	case "twilio":
		return s.sendTwilio(phone, message)
	default:
		return fmt.Errorf("unsupported SMS provider: %s", s.config.SMS.Provider)
	}
}

func (s *SMSService) getMessageByPurpose(purpose, code string) string {
	messages := map[string]string{
		"registration":   "Код подтверждения регистрации: %s. Никому не сообщайте этот код.",
		"password_reset": "Код восстановления пароля: %s. Никому не сообщайте этот код.",
		"2fa":            "Код для входа: %s",
	}

	template := messages[purpose]
	if template == "" {
		template = messages["registration"]
	}

	return fmt.Sprintf(template, code)
}

func (s *SMSService) sendSMSRu(phone, message string) error {
	// Очистка номера телефона
	cleanPhone := strings.ReplaceAll(phone, "+", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, " ", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "-", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "(", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, ")", "")

	// Подготовка параметров
	params := url.Values{}
	params.Set("api_id", s.config.SMS.APIKey)
	params.Set("to", cleanPhone)
	params.Set("msg", message)
	params.Set("json", "1")

	if s.config.SMS.FromName != "" {
		params.Set("from", s.config.SMS.FromName)
	}

	// Отправка запроса
	resp, err := s.client.R().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetBody(params.Encode()).
		Post("https://sms.ru/sms/send")

	if err != nil {
		return fmt.Errorf("failed to send SMS: %w", err)
	}

	// Парсинг ответа
	var result struct {
		Status     string `json:"status"`
		StatusCode int    `json:"status_code"`
		SMS        map[string]struct {
			Status     string `json:"status"`
			StatusCode int    `json:"status_code"`
			SMSID      string `json:"sms_id"`
		} `json:"sms"`
	}

	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return fmt.Errorf("failed to parse SMS response: %w", err)
	}

	if result.Status != "OK" {
		return fmt.Errorf("SMS sending failed with status: %s (code: %d)", result.Status, result.StatusCode)
	}

	return nil
}

func (s *SMSService) sendTwilio(phone, message string) error {
	// Twilio API implementation
	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", s.config.SMS.APIKey)

	params := url.Values{}
	params.Set("To", phone)
	params.Set("From", s.config.SMS.FromName)
	params.Set("Body", message)

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}

	req.SetBasicAuth(s.config.SMS.APIKey, s.config.SMS.APISecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send Twilio SMS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("Twilio API returned status: %d", resp.StatusCode)
	}

	return nil
}
