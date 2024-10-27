package routes

import (
	"micro/internal/handlers"
	"micro/internal/repositories"
	"micro/internal/services"

	"github.com/gofiber/fiber/v2"
)

func AuthRoutes(app *fiber.App) {
	userRepo := repositories.NewUserRepository()
	authService := services.NewAuthService(userRepo)
	authHandler := handlers.NewAuthHandler(authService)

	app.Post("/login", authHandler.Login)
	app.Post("/register", authHandler.Register)
}


