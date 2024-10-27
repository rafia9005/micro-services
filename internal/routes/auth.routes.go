package routes

import (
	"micro/internal/handlers"

	"github.com/gofiber/fiber/v2"
)

func AuthRoutes(router fiber.Router) {
	router.Post("/auth/login", handlers.Login)
	router.Post("/auth/register", handlers.Register)

  router.Get("/auth/google", handlers.AuthGoogle)
  router.Get("/auth/google/callback", handlers.CallbackAuthGoogle)

  router.Get("/auth/github", handlers.AuthGithub)
  router.Get("/auth/github/callback", handlers.CallbackAuthGithub)
}
