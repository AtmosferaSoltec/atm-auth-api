package access

import (
	"strings"
	"time"
	"unicode"
)

const maxRoleLength = 64

// Access says that a user may enter a system, inside one tenant, with a role.
// The role is free text: each system defines its own roles.
type Access struct {
	ID       string
	UserID   string
	SystemID string
	TenantID string
	Role     string
	// ManageUsers lets the user add and remove members of their own tenant in this system.
	ManageUsers bool
	CreatedAt   time.Time
}

// Detail is an access with the names needed to display it.
type Detail struct {
	Access
	SystemCode string
	SystemName string
	TenantName string
	// UserDNI and UserName are filled when listing by system.
	UserDNI  string
	UserName string
}

// Grant is a resolved, currently valid access: user active elsewhere, system, tenant and tenant-system all active.
type Grant struct {
	SystemID    string
	SystemCode  string
	TenantID    string
	Role        string
	ManageUsers bool
	// SessionMode is the system's session policy: "persistent" or "temporary".
	SessionMode string
	// TenantRUC, UserDNI and UserName let the consuming system link or create its own record of the person
	// and the company without asking anything else.
	TenantRUC string
	UserDNI   string
	UserName  string
}

// NormalizeRole trims role and reports whether it is acceptable.
func NormalizeRole(role string) (string, bool) { return normalizeRole(role) }

func normalizeRole(role string) (string, bool) {
	role = strings.TrimSpace(role)
	if role == "" || len([]rune(role)) > maxRoleLength {
		return "", false
	}
	for _, r := range role {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return role, true
}

// Option is a company a person can work for in a system.
type Option struct {
	TenantID string
	RUC      string
	// Name is the trade name, or the legal name when there is none.
	Name string
	// Role is what the person is in that company.
	Role string
}
