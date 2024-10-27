package services

import (
	"fmt"
	"micro/internal/middleware"
	"micro/internal/models/entity"
	"micro/internal/models/request"
	"micro/internal/repositories"
	"micro/internal/utils"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator/v10"
)

type AuthService struct {
	userRepo repositories.UserRepository
}

func NewAuthService(userRepo repositories.UserRepository) *AuthService {
	return &AuthService{userRepo: userRepo}
}

func ValidateLogin(loginRequest *request.LoginRequest) error {
	validate := validator.New()
	return validate.Struct(loginRequest)
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

func (s *AuthService) HashAndStoreUser(registerRequest *request.RegisterRequest) (string, error) {
	// Cek apakah pengguna sudah ada
	if _, err := s.userRepo.GetByEmail(registerRequest.Email); err == nil {
		return "", fmt.Errorf("user with email %s already exists", registerRequest.Email)
	}

	// Hash password
	hashedPassword, err := middleware.HashPassword(registerRequest.Password)
	if err != nil {
		return "", err
	}

	// Buat pengguna baru
	newUser := entity.Users{
		Name:      fmt.Sprintf("%s %s", registerRequest.FirstName, registerRequest.LastName),
		FirstName: registerRequest.FirstName,
		LastName:  registerRequest.LastName,
		Email:     registerRequest.Email,
		Password:  hashedPassword,
		Role:      "member",
		Verify:    true,
	}

	// Simpan pengguna baru di database
	if err := s.userRepo.Create(&newUser); err != nil {
		return "", err
	}

	return fmt.Sprintf("User %s registered successfully", newUser.Email), nil
}

func (s *AuthService) AuthenticateUser(email, password string) (*entity.Users, error) {
	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		return nil, err
	}

	if !middleware.CheckPassword(user.Password, password) {
		return nil, fmt.Errorf("invalid password")
	}

	return user, nil
}
