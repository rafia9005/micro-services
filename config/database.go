package config

import (
	"fmt"
	"micro/internal/models/entity"
	"os"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Connect() error {
	dsn := os.Getenv("APP_MYSQL")
	fmt.Println(dsn)

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		fmt.Println("Failed to connect database!")
		return err
	}

	DB = db

	fmt.Println("Database is connected!")

	if err := DB.AutoMigrate(&entity.Users{}); err != nil {
		fmt.Println("Failed to auto-migrate:", err)
		return err
	}

	fmt.Println("Auto migration completed successfully!")
	return nil
}

