package db

import (
	"database/sql"
	"time"
)

type OmniDatabase struct {
	Db *sql.DB
}

type Client struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	TenantId    string    `json:"tenantId"`
	PhoneNumber string    `json:"phoneNumber"`
	CreatedAt   time.Time `json:"createdAt"`
}

type WhatsappAccount struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenantIdId"`
	AccessToken string `json:"accessToken"`
}
