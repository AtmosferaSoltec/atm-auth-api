package system

import (
	"regexp"
	"strings"
	"time"
)

const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

const (
	// SessionPersistent remembers the user: the refresh token lasts the global REFRESH_TOKEN_TTL.
	SessionPersistent = "persistent"
	// SessionTemporary signs the user out after SessionMinutes of inactivity.
	SessionTemporary = "temporary"

	MinSessionMinutes = 5
	MaxSessionMinutes = 1440
)

var codePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

type System struct {
	ID     string
	Code   string
	Name   string
	Status string
	// SessionMode is SessionPersistent or SessionTemporary.
	SessionMode string
	// SessionMinutes is the inactivity limit of a temporary session, and 0 for a persistent one.
	SessionMinutes int
	// HasSecret says whether the system has a secret to ask for service tokens. The secret itself is never exposed.
	HasSecret        bool
	SecretCreatedAt  *time.Time
	SecretLastUsedAt *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

func validCode(code string) bool { return codePattern.MatchString(code) }

func normalizeName(name string) string { return strings.Join(strings.Fields(name), " ") }

// normalizeSession validates a session policy. A persistent policy carries no minutes.
func normalizeSession(mode string, minutes int) (string, int, error) {
	switch mode {
	case "", SessionPersistent:
		return SessionPersistent, 0, nil
	case SessionTemporary:
		if minutes < MinSessionMinutes || minutes > MaxSessionMinutes {
			return "", 0, ErrInvalidSessionMinutes
		}
		return SessionTemporary, minutes, nil
	default:
		return "", 0, ErrInvalidSessionMode
	}
}
