// Package role manages the catalog of roles each system defines.
package role

import (
	"strings"
	"time"
	"unicode"
)

const maxDescriptionLength = 200

// Role is a role a system defines. The platform does not know what it allows: that is up to the system.
type Role struct {
	ID          string
	SystemID    string
	Name        string
	Description string
	// Users is how many people have this role today. Filled by List.
	Users     int
	CreatedAt time.Time
}

func normalizeDescription(description string) (string, bool) {
	description = strings.TrimSpace(description)
	if len([]rune(description)) > maxDescriptionLength {
		return "", false
	}
	for _, r := range description {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return description, true
}
