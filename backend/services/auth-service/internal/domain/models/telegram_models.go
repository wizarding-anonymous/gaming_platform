package models

// TelegramAuthData represents the data received from Telegram for authentication.
type TelegramAuthData struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name,omitempty"`
	Username  string `json:"username,omitempty"`
	PhotoURL  string `json:"photo_url,omitempty"`
	AuthDate  int64  `json:"auth_date"`
	Hash      string `json:"hash"`
}

// TelegramProfile represents the verified user profile information from Telegram.
type TelegramProfile struct {
	ID         int64  `json:"id"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name,omitempty"`
	Username   string `json:"username,omitempty"`
	PhotoURL   string `json:"photo_url,omitempty"`
	AuthDate   int64  `json:"auth_date"` // Included as it's part of the data from Telegram
}
