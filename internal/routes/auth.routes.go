package routes

import (
	"micro/internal/handlers"

	"github.com/gofiber/fiber/v2"
)


func AuthRoutes(app *fiber.App) {
    app.Post("/login", handlers.Login)
    app.Post("/register", handlers.Register)
}
