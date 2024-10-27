package repositories

import (
	"micro/config"
	"micro/internal/models/entity"
)

type UserRepository interface {
	GetByEmail(email string) (*entity.Users, error)
	Create(user *entity.Users) error
	Update(user *entity.Users) error
}

type userRepository struct{}

func NewUserRepository() UserRepository {
	return &userRepository{}
}

func (r *userRepository) GetByEmail(email string) (*entity.Users, error) {
	var user entity.Users
	err := config.DB.First(&user, "email = ?", email).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) Create(user *entity.Users) error {
	return config.DB.Create(user).Error
}

func (r *userRepository) Update(user *entity.Users) error {
	return config.DB.Save(user).Error
}

