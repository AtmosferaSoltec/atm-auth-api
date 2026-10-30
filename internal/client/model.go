package client

import (
	"strings"
	"time"
)

const maxName = 200

// TenantRef is a company that belongs to a client.
type TenantRef struct {
	ID          string
	RUC         string
	DisplayName string
}

// Client is the owner of one or more companies. Systems use it to decide what the companies of one owner share.
type Client struct {
	ID        string
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
	// Tenants are the companies of the client, ordered by name. Filled by GetByID and List.
	Tenants []TenantRef
}

func normalizeName(name string) string { return strings.Join(strings.Fields(name), " ") }
