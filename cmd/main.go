package main

import (
	"log"
	"micro/config"
	"micro/internal/routes"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
)

func main() {
	app := fiber.New()

	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

  config.Connect()
	routes.AuthRoutes(app)

	app.Listen(":3000")
}
