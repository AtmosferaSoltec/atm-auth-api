package session

import "time"

const (
	RoleSuperadmin = "superadmin"
	RoleUser       = "user"
	// RoleService is the role of a system's backend. Its tokens open no admin or tenant route.
	RoleService = "service"

	// AdminSubject is the JWT subject of the superadmin, which has no row in users.
	AdminSubject = "admin"
)

// RefreshToken is a stored refresh token. Only its hash is persisted.
type RefreshToken struct {
	ID         string
	FamilyID   string
	TokenHash  string
	Role       string
	UserID     string
	SystemID   string
	SystemCode string
	// TenantID is the company the session works for ("" for the superadmin). A refresh keeps it.
	TenantID  string
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
}

// Tokens is the result of a successful login or refresh.
type Tokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
	// RefreshExpiresIn is how many seconds the refresh token stays valid without being used.
	RefreshExpiresIn int
	// SessionMode is "persistent" or "temporary": whether clients may remember the session.
	SessionMode string
}

// Limits configures login throttling.
type Limits struct {
	MaxPerSubject int
	MaxPerIP      int
	Window        time.Duration
}

// AdminCredentials are the superadmin credentials loaded from the environment.
type AdminCredentials struct {
	DNI          string
	PasswordHash string
}
