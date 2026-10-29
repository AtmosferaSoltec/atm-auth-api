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
	TenantName string
}

// Grant is a resolved, currently valid access: user active elsewhere, system, tenant and tenant-system all active.
type Grant struct {
	SystemID    string
	SystemCode  string
	TenantID    string
	Role        string
	ManageUsers bool
}

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
