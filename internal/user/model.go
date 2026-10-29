package user

import (
	"regexp"
	"strings"
	"time"
)

const (
	StatusActive   = "active"
	StatusDisabled = "disabled"

	MinPasswordLength = 8
)

// ValidStatus reports whether s is a known account status.
func ValidStatus(s string) bool { return s == StatusActive || s == StatusDisabled }

// ValidNewPassword reports whether password is acceptable as a new password for the account with this DNI.
func ValidNewPassword(password, dni string) bool {
	return len(password) >= MinPasswordLength && password != dni
}

var dniPattern = regexp.MustCompile(`^[0-9]{8}$`)

type User struct {
	ID           string
	DNI          string
	FullName     string
	PasswordHash string
	Status       string
	// MustChangePassword is set while the account still has its initial password (the DNI).
	MustChangePassword bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// ValidDNI reports whether dni has the 8-digit form.
func ValidDNI(dni string) bool { return dniPattern.MatchString(dni) }

func validDNI(dni string) bool { return ValidDNI(dni) }

func normalizeName(name string) string { return strings.Join(strings.Fields(name), " ") }
