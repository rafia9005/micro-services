package handlers

import (
	"context"
	"fmt"
	"micro/internal/models/request"
	"micro/internal/provider"
	"micro/internal/services"

	"github.com/gofiber/fiber/v2"
)

func Login(c *fiber.Ctx) error {
	loginRequest := new(request.LoginRequest)
	if err := c.BodyParser(loginRequest); err != nil {
		return err
	}

	if errValidate := services.ValidateLogin(loginRequest); errValidate != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Validation failed",
			"error":   errValidate.Error(),
		})
	}

	user, err := services.AuthenticateUser(loginRequest.Email, loginRequest.Password)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Invalid email or password",
		})
	}

	if !user.Verify {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"message": "Account not verified. Please check your email for verification instructions.",
		})
	}

	token, errGenerateToken := services.GenerateJWTToken(user)
	if errGenerateToken != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Error generating token",
		})
	}

	return c.JSON(fiber.Map{
		"status": true,
		"token":  token,
	})
}

func Register(c *fiber.Ctx) error {
	registerRequest := new(request.RegisterRequest)
	if err := c.BodyParser(registerRequest); err != nil {
		return err
	}

	if errValidate := services.ValidateRegister(registerRequest); errValidate != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Validation failed",
			"error":   errValidate.Error(),
		})
	}

	result, err := services.HashAndStoreUser(registerRequest)
	if err != nil {
		if err.Error() == fmt.Sprintf("user with email %s already exists", registerRequest.Email) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"message": "Email already in use",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to register user",
		})
	}

	return c.JSON(fiber.Map{
		"status":  result,
		"message": "Registration successful! Please check your email for the verification code",
	})
}

func VerifyCode(c *fiber.Ctx) error {
	type VerifyRequest struct {
		Token string `json:"token"`
	}

	verifyRequest := new(VerifyRequest)
	if err := c.BodyParser(verifyRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid request",
		})
	}

	verifyToken, err := services.GetVerifyToken(verifyRequest.Token)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"message": "Invalid or expired verification code",
		})
	}

	user, err := services.GetUserByID(verifyToken.UserID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"message": "User not found",
		})
	}

	user.Verify = true
	if err := services.UpdateUser(user); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to verify user",
		})
	}

	if err := services.DeleteVerifyToken(verifyToken.ID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to delete verification token",
		})
	}

	return c.JSON(fiber.Map{
		"status":  true,
		"message": "Email verified successfully",
	})
}

func ResendVerifyRequest(c *fiber.Ctx) error {
	resendRequest := new(request.ResendVerifyRequest)
	if err := c.BodyParser(resendRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid request",
		})
	}

	user, err := services.GetUserByEmail(resendRequest.Email)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"message": "User not found",
		})
	}

	if user.Verify {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Account is already verified",
		})
	}

	if err := services.DeleteVerifyTokenByUserID(user.ID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to delete old verification token",
		})
	}

	if err := services.GenerateAndSendVerificationToken(user); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to generate and send verification token",
		})
	}

	return c.JSON(fiber.Map{
		"status":  true,
		"message": "Verification token has been resent. Please check your email.",
	})
}

// Oauth google provider

func AuthGoogle(c *fiber.Ctx) error {
	form := c.Query("from", "/")
	url := services.GetGoogleAuthURL(form)
	return c.Redirect(url)
}

func CallbackAuthGoogle(c *fiber.Ctx) error {
	code := c.Query("code")
	if code == "" {
		return c.Status(401).JSON(fiber.Map{
			"status":  "error",
			"message": "Authorization code is missing",
		})
	}

	token, err := provider.GoogleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to exchange authorization code for token",
		})
	}

	userInfo, err := services.GetGoogleUserInfo(token)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": fmt.Sprintf("Failed to get user info: %v", err),
		})
	}

	email, emailExists := userInfo["email"].(string)
	givenName := userInfo["given_name"].(string)
	familyName := userInfo["family_name"].(string)

	if !emailExists {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "Email is missing from user info",
		})
	}

	existingUser, err := services.GetUserByEmail(email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if saveErr := services.SaveGoogleUser(givenName, familyName, email); saveErr != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": fmt.Sprintf("Failed to save new user data: %v", saveErr),
				})
			}
			existingUser, err = services.GetUserByEmail(email)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Failed to fetch the newly created user",
				})
			}
			jwtToken, err := services.GenerateJWTToken(existingUser)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Failed to generate JWT token",
				})
			}

			return c.JSON(fiber.Map{
				"status":  "success",
				"token":   jwtToken,
				"message": "Registered with Google successfully",
			})
		} else {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": fmt.Sprintf("Failed to check if user exists: %v", err),
			})
		}
	}

	if existingUser.Provider != nil && *existingUser.Provider != "google" {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": fmt.Sprintf("Your account is already registered with provider '%s'", *existingUser.Provider),
		})
	}

	jwtToken, err := services.GenerateJWTToken(existingUser)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to generate JWT token",
		})
	}

	return c.JSON(fiber.Map{
		"status":  "success",
		"message": "User already exists",
		"token":   jwtToken,
		"data": fiber.Map{
			"user": request.UserResponse{
				ID:        existingUser.ID,
				Name:      existingUser.Name,
				FirstName: existingUser.FirstName,
				LastName:  existingUser.LastName,
				Email:     existingUser.Email,
				CreatedAt: existingUser.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
				UpdatedAt: existingUser.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
			},
		},
	})
}

// GITHU PROVIDER

func AuthGithub(c *fiber.Ctx) error {
	form := c.Query("from", "/")
	url := services.GetGithubAuthUrl(form)
	return c.Redirect(url)
}

func CallbackAuthGithub(c *fiber.Ctx) error {
	code := c.Query("code")
	if code == "" {
		return c.Status(401).JSON(fiber.Map{
			"status":  "error",
			"message": "Authorization code is missing",
		})
	}

	token, err := provider.GithubOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		fmt.Printf("Error exchanging code for token: %v\n", err)
		return c.Status(401).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to exchange authorization code for token",
		})
	}

	userInfo, err := services.GetGithubUserInfo(token)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": fmt.Sprintf("Failed to get user info: %v", err),
		})
	}

	email, err := services.GetGithubUserPrimaryEmail(token)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": fmt.Sprintf("Failed to get user email: %v", err),
		})
	}

	existingUser, err := services.GetUserByEmail(email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {

			var firstName, lastName string
			if name, ok := userInfo["name"].(string); ok {
				nameParts := strings.Fields(name)
				if len(nameParts) > 0 {
					firstName = nameParts[0]
					if len(nameParts) > 1 {
						lastName = strings.Join(nameParts[1:], " ")
					}
				}
			}
			if saveErr := services.SaveGithubUser(firstName, lastName, email); saveErr != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": fmt.Sprintf("Failed to save new user data: %v", saveErr),
				})
			}
			existingUser, err = services.GetUserByEmail(email)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Failed to fetch the newly created user",
				})
			}
			jwtToken, err := services.GenerateJWTToken(existingUser)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Failed to generate JWT token",
				})
			}

			return c.JSON(fiber.Map{
				"status":  "success",
				"token":   jwtToken,
				"message": "Registered with Github successfully",
			})
		} else {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": fmt.Sprintf("Failed to check if user exists: %v", err),
			})
		}
	}

	if existingUser.Provider != nil && *existingUser.Provider != "github" {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": fmt.Sprintf("Your account is already registered with provider '%s'", *existingUser.Provider),
		})
	}

	jwtToken, err := services.GenerateJWTToken(existingUser)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to generate JWT token",
		})
	}

	return c.JSON(fiber.Map{
		"status":  "success",
		"message": "User already exists",
		"token":   jwtToken,
		"data": fiber.Map{
			"user": request.UserResponse{
				ID:        existingUser.ID,
				Name:      existingUser.Name,
				FirstName: existingUser.FirstName,
				LastName:  existingUser.LastName,
				Email:     existingUser.Email,
				CreatedAt: existingUser.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
				UpdatedAt: existingUser.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
			},
		},
	})
}
