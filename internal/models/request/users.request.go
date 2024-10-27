package request

type Contacts struct {
	Phone *string `json:"phone"`
	Bio   *string `json:"bio"`
}

type UserProfile struct {
	Name      string   `json:"name"`
	FirstName string   `json:"first_name"`
	LastName  string   `json:"last_name"`
	Email     string   `json:"email"`
	Role      string   `json:"role"`
	Verify    bool     `json:"verify"`
	CreatedAt string   `json:"createdAt"`
	UpdatedAt string   `json:"updatedAt"`
	Contacts  Contacts `json:"contacts"`
}

type UpdateUserProfileRequest struct {
	ID       uint     `json:"id"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Contacts Contacts `json:"contacts"`
}

type UserResponse struct {
	ID        uint     `json:"id"`
	Name      string   `json:"name"`
	FirstName string   `json:"first_name"`
	LastName  string   `json:"last_name"`
	Email     string   `json:"email"`
	CreatedAt string   `json:"createdAt"`
	UpdatedAt string   `json:"updatedAt"`
	Contacts  Contacts `json:"contacts"`
}
