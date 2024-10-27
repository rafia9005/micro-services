package services

import (
	"context"
	"encoding/json"
	"fmt"
	"micro/config"
	"micro/internal/middleware"
	"micro/internal/models/entity"
	"micro/internal/models/request"
	"micro/internal/provider"
	"micro/internal/utils"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator/v10"
	"golang.org/x/oauth2"
)

func ValidateLogin(loginRequest *request.LoginRequest) error {
	validate := validator.New()
	return validate.Struct(loginRequest)
}

func GetUserByEmail(email string) (*entity.Users, error) {
	var user entity.Users
	err := config.DB.First(&user, "email = ?", email).Error
	return &user, err
}

func GenerateJWTToken(user *entity.Users) (string, error) {
	claims := jwt.MapClaims{
		"id":    user.ID,
		"name":  user.Name,
		"email": user.Email,
		"exp":   time.Now().Add(time.Hour * 24 * 7).Unix(),
		"role":  "member",
	}

	if user.Role == "admin" {
		claims["role"] = "admin"
	}

	return utils.GenerateToken(&claims)
}

func ValidateRegister(registerRequest *request.RegisterRequest) error {
	validate := validator.New()
	return validate.Struct(registerRequest)
}

func HashAndStoreUser(registerRequest *request.RegisterRequest) (string, error) {
	var existingUser entity.Users
	if err := config.DB.First(&existingUser, "email = ?", registerRequest.Email).Error; err == nil {
		return "", fmt.Errorf("user with email %s already exists", registerRequest.Email)
	}

	hashedPassword, err := middleware.HashPassword(registerRequest.Password)
	if err != nil {
		return "", err
	}

	newUser := entity.Users{
		Name:      fmt.Sprintf("%s %s", registerRequest.FirstName, registerRequest.LastName),
		FirstName: registerRequest.FirstName,
		LastName:  registerRequest.LastName,
		Email:     registerRequest.Email,
		Password:  hashedPassword,
		Role:      "member",
		Verify:    true,
	}

	if err := config.DB.Create(&newUser).Error; err != nil {
		return "", err
	}

	return fmt.Sprintf("User %s registered successfully", newUser.Email), nil
}

func UpdateUser(user *entity.Users) error {
	return config.DB.Save(user).Error
}

func AuthenticateUser(email, password string) (*entity.Users, error) {
	var user entity.Users
	err := config.DB.First(&user, "email = ?", email).Error
	if err != nil {
		return nil, err
	}

	if !middleware.CheckPassword(user.Password, password) {
		return nil, fmt.Errorf("invalid password")
	}

	return &user, nil
}

func GetGoogleAuthURL(redirectURI string) string {
	return provider.GoogleOauthConfig.AuthCodeURL(redirectURI)
}

func GetGithubAuthUrl(redirectURI string) string {
	return provider.GithubOauthConfig.AuthCodeURL(redirectURI)
}

func GetGoogleUserInfo(token *oauth2.Token) (map[string]interface{}, error) {
	client := provider.GoogleOauthConfig.Client(context.Background(), token)

	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info: status code %d", resp.StatusCode)
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return userInfo, nil
}

func GetGithubUserInfo(token *oauth2.Token) (map[string]interface{}, error) {
	client := provider.GithubOauthConfig.Client(context.Background(), token)

	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info: status code %d", resp.StatusCode)
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return userInfo, nil
}

func GetGithubUserPrimaryEmail(token *oauth2.Token) (string, error) {
	client := provider.GithubOauthConfig.Client(context.Background(), token)

	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", fmt.Errorf("failed to get user emails: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get user emails: status code %d", resp.StatusCode)
	}

	var emails []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", fmt.Errorf("failed to decode user emails: %w", err)
	}

	for _, e := range emails {
		if primary, ok := e["primary"].(bool); ok && primary {
			if email, ok := e["email"].(string); ok {
				return email, nil
			}
		}
	}

	return "", fmt.Errorf("no primary email found")
}

func SaveGoogleUser(firstName, lastName, email string) error {
	provider := "google"
	newUser := entity.Users{
		Name:      fmt.Sprintf("%s %s", firstName, lastName),
		FirstName: firstName,
		LastName:  lastName,
		Email:     email,
		Role:      "member",
		Verify:    true,
		Provider:  &provider,
	}

	if err := config.DB.Create(&newUser).Error; err != nil {
		return err
	}
	return nil
}

func SaveGithubUser(fristName, lastName, email string) error {
	provider := "github"
	newUser := entity.Users{
		Name:      fmt.Sprintf("%s %s", fristName, lastName),
		FirstName: fristName,
		LastName:  lastName,
		Email:     email,
		Role:      "member",
		Verify:    true,
		Provider:  &provider,
	}

	if err := config.DB.Create(&newUser).Error; err != nil {
		return err
	}

	return nil
}
