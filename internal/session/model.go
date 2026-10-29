package session

import "time"

const (
	RoleSuperadmin = "superadmin"
	RoleUser       = "user"

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
	ExpiresAt  time.Time
	UsedAt     *time.Time
	RevokedAt  *time.Time
}

// Tokens is the result of a successful login or refresh.
type Tokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
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
