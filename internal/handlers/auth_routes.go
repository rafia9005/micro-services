package handlers

import "github.com/gofiber/fiber/v2"


func Setup(app *fiber.App) {
    app.Get("/register")
}
