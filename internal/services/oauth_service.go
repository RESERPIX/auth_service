// internal/services/oauth_service.go
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/RESERPIX/auth_service/internal/config"
	"github.com/go-resty/resty/v2"
)

type OAuthService struct {
	config *config.Config
	client *resty.Client
}

type OAuthUserInfo struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FullName  string `json:"full_name"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Phone     string `json:"phone"`
	Avatar    string `json:"avatar"`
	Provider  string `json:"provider"`
}

func NewOAuthService(config *config.Config) *OAuthService {
	return &OAuthService{
		config: config,
		client: resty.New(),
	}
}

// Получение URL для авторизации
func (s *OAuthService) GetAuthURL(provider, state, redirectURI string) (string, error) {
	switch provider {
	case "yandex":
		return s.getYandexAuthURL(state, redirectURI), nil
	case "mail":
		return s.getMailAuthURL(state, redirectURI), nil
	case "vk":
		return s.getVKAuthURL(state, redirectURI), nil
	case "gosuslugi":
		return s.getGosuslugiAuthURL(state, redirectURI), nil
	default:
		return "", fmt.Errorf("unsupported OAuth provider: %s", provider)
	}
}

// Обмен кода на токен и получение информации о пользователе
func (s *OAuthService) ExchangeCodeForUserInfo(ctx context.Context, provider, code, state, redirectURI string) (*OAuthUserInfo, error) {
	switch provider {
	case "yandex":
		return s.exchangeYandexCode(ctx, code, redirectURI)
	case "mail":
		return s.exchangeMailCode(ctx, code, redirectURI)
	case "vk":
		return s.exchangeVKCode(ctx, code, redirectURI)
	case "gosuslugi":
		return s.exchangeGosuslugiCode(ctx, code, redirectURI)
	default:
		return nil, fmt.Errorf("unsupported OAuth provider: %s", provider)
	}
}

// Yandex OAuth
func (s *OAuthService) getYandexAuthURL(state, redirectURI string) string {
	baseURL := "https://oauth.yandex.ru/authorize"
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", s.config.OAuth.Yandex.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("state", state)
	params.Set("scope", "login:email login:info")

	return fmt.Sprintf("%s?%s", baseURL, params.Encode())
}

func (s *OAuthService) exchangeYandexCode(ctx context.Context, code, redirectURI string) (*OAuthUserInfo, error) {
	// Обмен кода на токен
	tokenResp, err := s.client.R().
		SetContext(ctx).
		SetFormData(map[string]string{
			"grant_type":    "authorization_code",
			"code":          code,
			"client_id":     s.config.OAuth.Yandex.ClientID,
			"client_secret": s.config.OAuth.Yandex.ClientSecret,
			"redirect_uri":  redirectURI,
		}).
		Post("https://oauth.yandex.ru/token")

	if err != nil {
		return nil, fmt.Errorf("failed to exchange Yandex code: %w", err)
	}

	var tokenData struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.Unmarshal(tokenResp.Body(), &tokenData); err != nil {
		return nil, fmt.Errorf("failed to parse Yandex token response: %w", err)
	}

	// Получение информации о пользователе
	userResp, err := s.client.R().
		SetContext(ctx).
		SetAuthToken(tokenData.AccessToken).
		Get("https://login.yandex.ru/info")

	if err != nil {
		return nil, fmt.Errorf("failed to get Yandex user info: %w", err)
	}

	var userData struct {
		ID           string   `json:"id"`
		Login        string   `json:"login"`
		ClientID     string   `json:"client_id"`
		DisplayName  string   `json:"display_name"`
		RealName     string   `json:"real_name"`
		FirstName    string   `json:"first_name"`
		LastName     string   `json:"last_name"`
		Sex          string   `json:"sex"`
		DefaultEmail string   `json:"default_email"`
		Emails       []string `json:"emails"`
		DefaultPhone struct {
			ID     int    `json:"id"`
			Number string `json:"number"`
		} `json:"default_phone"`
		DefaultAvatarID string `json:"default_avatar_id"`
	}

	if err := json.Unmarshal(userResp.Body(), &userData); err != nil {
		return nil, fmt.Errorf("failed to parse Yandex user response: %w", err)
	}

	userInfo := &OAuthUserInfo{
		ID:        userData.ID,
		Email:     userData.DefaultEmail,
		FullName:  userData.RealName,
		FirstName: userData.FirstName,
		LastName:  userData.LastName,
		Provider:  "yandex",
	}

	if userData.DefaultPhone.Number != "" {
		userInfo.Phone = userData.DefaultPhone.Number
	}

	if userData.DefaultAvatarID != "" {
		userInfo.Avatar = fmt.Sprintf("https://avatars.yandex.net/get-yapic/%s/islands-200", userData.DefaultAvatarID)
	}

	return userInfo, nil
}

// Mail.ru OAuth
func (s *OAuthService) getMailAuthURL(state, redirectURI string) string {
	baseURL := "https://oauth.mail.ru/login"
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", s.config.OAuth.Mail.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("state", state)
	params.Set("scope", "userinfo")

	return fmt.Sprintf("%s?%s", baseURL, params.Encode())
}

func (s *OAuthService) exchangeMailCode(ctx context.Context, code, redirectURI string) (*OAuthUserInfo, error) {
	// Обмен кода на токен
	tokenResp, err := s.client.R().
		SetContext(ctx).
		SetFormData(map[string]string{
			"grant_type":    "authorization_code",
			"code":          code,
			"client_id":     s.config.OAuth.Mail.ClientID,
			"client_secret": s.config.OAuth.Mail.ClientSecret,
			"redirect_uri":  redirectURI,
		}).
		Post("https://oauth.mail.ru/token")

	if err != nil {
		return nil, fmt.Errorf("failed to exchange Mail.ru code: %w", err)
	}

	var tokenData struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.Unmarshal(tokenResp.Body(), &tokenData); err != nil {
		return nil, fmt.Errorf("failed to parse Mail.ru token response: %w", err)
	}

	// Получение информации о пользователе
	userResp, err := s.client.R().
		SetContext(ctx).
		SetQueryParam("access_token", tokenData.AccessToken).
		Get("https://oauth.mail.ru/userinfo")

	if err != nil {
		return nil, fmt.Errorf("failed to get Mail.ru user info: %w", err)
	}

	var userData struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		Name      string `json:"name"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Nickname  string `json:"nickname"`
		Birthday  string `json:"birthday"`
		Gender    string `json:"gender"`
		Image     string `json:"image"`
	}

	if err := json.Unmarshal(userResp.Body(), &userData); err != nil {
		return nil, fmt.Errorf("failed to parse Mail.ru user response: %w", err)
	}

	return &OAuthUserInfo{
		ID:        userData.ID,
		Email:     userData.Email,
		FullName:  userData.Name,
		FirstName: userData.FirstName,
		LastName:  userData.LastName,
		Avatar:    userData.Image,
		Provider:  "mail",
	}, nil
}

// VK OAuth
func (s *OAuthService) getVKAuthURL(state, redirectURI string) string {
	baseURL := "https://oauth.vk.com/authorize"
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", s.config.OAuth.VK.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("state", state)
	params.Set("scope", "email")
	params.Set("v", "5.131")

	return fmt.Sprintf("%s?%s", baseURL, params.Encode())
}

func (s *OAuthService) exchangeVKCode(ctx context.Context, code, redirectURI string) (*OAuthUserInfo, error) {
	// Обмен кода на токен
	tokenResp, err := s.client.R().
		SetContext(ctx).
		SetQueryParams(map[string]string{
			"client_id":     s.config.OAuth.VK.ClientID,
			"client_secret": s.config.OAuth.VK.ClientSecret,
			"redirect_uri":  redirectURI,
			"code":          code,
		}).
		Get("https://oauth.vk.com/access_token")

	if err != nil {
		return nil, fmt.Errorf("failed to exchange VK code: %w", err)
	}

	var tokenData struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		UserID      int    `json:"user_id"`
		Email       string `json:"email"`
	}

	if err := json.Unmarshal(tokenResp.Body(), &tokenData); err != nil {
		return nil, fmt.Errorf("failed to parse VK token response: %w", err)
	}

	// Получение информации о пользователе
	userResp, err := s.client.R().
		SetContext(ctx).
		SetQueryParams(map[string]string{
			"access_token": tokenData.AccessToken,
			"user_ids":     fmt.Sprintf("%d", tokenData.UserID),
			"fields":       "first_name,last_name,photo_200",
			"v":            "5.131",
		}).
		Get("https://api.vk.com/method/users.get")

	if err != nil {
		return nil, fmt.Errorf("failed to get VK user info: %w", err)
	}

	var userData struct {
		Response []struct {
			ID        int    `json:"id"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
			Photo200  string `json:"photo_200"`
		} `json:"response"`
	}

	if err := json.Unmarshal(userResp.Body(), &userData); err != nil {
		return nil, fmt.Errorf("failed to parse VK user response: %w", err)
	}

	if len(userData.Response) == 0 {
		return nil, fmt.Errorf("no user data returned from VK")
	}

	user := userData.Response[0]
	return &OAuthUserInfo{
		ID:        fmt.Sprintf("%d", user.ID),
		Email:     tokenData.Email,
		FullName:  fmt.Sprintf("%s %s", user.FirstName, user.LastName),
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Avatar:    user.Photo200,
		Provider:  "vk",
	}, nil
}

// Госуслуги OAuth
func (s *OAuthService) getGosuslugiAuthURL(state, redirectURI string) string {
	baseURL := "https://esia.gosuslugi.ru/aas/oauth2/authorize"
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", s.config.OAuth.Gosuslugi.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("state", state)
	params.Set("scope", "openid fullname email mobile")
	params.Set("access_type", "online")

	return fmt.Sprintf("%s?%s", baseURL, params.Encode())
}

func (s *OAuthService) exchangeGosuslugiCode(ctx context.Context, code, redirectURI string) (*OAuthUserInfo, error) {
	// Обмен кода на токен
	tokenResp, err := s.client.R().
		SetContext(ctx).
		SetFormData(map[string]string{
			"grant_type":    "authorization_code",
			"code":          code,
			"client_id":     s.config.OAuth.Gosuslugi.ClientID,
			"client_secret": s.config.OAuth.Gosuslugi.ClientSecret,
			"redirect_uri":  redirectURI,
		}).
		Post("https://esia.gosuslugi.ru/aas/oauth2/token")

	if err != nil {
		return nil, fmt.Errorf("failed to exchange Gosuslugi code: %w", err)
	}

	var tokenData struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}

	if err := json.Unmarshal(tokenResp.Body(), &tokenData); err != nil {
		return nil, fmt.Errorf("failed to parse Gosuslugi token response: %w", err)
	}

	// Получение информации о пользователе
	userResp, err := s.client.R().
		SetContext(ctx).
		SetAuthToken(tokenData.AccessToken).
		Get("https://esia.gosuslugi.ru/rs/prns/")

	if err != nil {
		return nil, fmt.Errorf("failed to get Gosuslugi user info: %w", err)
	}

	var userData struct {
		PersonOID  string `json:"personOID"`
		FirstName  string `json:"firstName"`
		LastName   string `json:"lastName"`
		MiddleName string `json:"middleName"`
		BirthDate  string `json:"birthDate"`
		Gender     string `json:"gender"`
		Snils      string `json:"snils"`
		Inn        string `json:"inn"`
		UpdatedOn  int64  `json:"updatedOn"`
		Status     string `json:"status"`
		Contacts   []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
			Vrfed bool   `json:"vrfed"`
		} `json:"contacts"`
	}

	if err := json.Unmarshal(userResp.Body(), &userData); err != nil {
		return nil, fmt.Errorf("failed to parse Gosuslugi user response: %w", err)
	}

	userInfo := &OAuthUserInfo{
		ID:        userData.PersonOID,
		FirstName: userData.FirstName,
		LastName:  userData.LastName,
		Provider:  "gosuslugi",
	}

	// Формирование полного имени
	if userData.MiddleName != "" {
		userInfo.FullName = fmt.Sprintf("%s %s %s", userData.FirstName, userData.MiddleName, userData.LastName)
	} else {
		userInfo.FullName = fmt.Sprintf("%s %s", userData.FirstName, userData.LastName)
	}

	// Извлечение email и телефона из контактов
	for _, contact := range userData.Contacts {
		switch contact.Type {
		case "EML":
			if contact.Vrfed {
				userInfo.Email = contact.Value
			}
		case "MBT":
			if contact.Vrfed {
				userInfo.Phone = contact.Value
			}
		}
	}

	return userInfo, nil
}

// Вспомогательные методы для работы с состоянием OAuth
func (s *OAuthService) GenerateState() string {
	// Простая генерация state для защиты от CSRF
	// В продакшене лучше использовать криптографически стойкий генератор
	return fmt.Sprintf("state_%d", time.Now().UnixNano())
}

func (s *OAuthService) ValidateState(receivedState, expectedState string) bool {
	return receivedState == expectedState
}
