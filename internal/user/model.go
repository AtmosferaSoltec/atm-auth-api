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
	ID string
	// DNI is empty for people who sign in with an email only.
	DNI string
	// Email is empty for people who only have a DNI. It is stored trimmed and in lower case.
	Email         string
	EmailVerified bool
	FullName      string
	// PasswordHash is empty for accounts that have no password yet (created with Google).
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

var emailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

// NormalizeEmail trims and lower-cases an email and reports whether it has a valid form.
func NormalizeEmail(email string) (string, bool) {
	email = strings.ToLower(strings.TrimSpace(email))
	if len(email) < 3 || len(email) > 254 || !emailPattern.MatchString(email) {
		return "", false
	}
	return email, true
}

func normalizeName(name string) string { return strings.Join(strings.Fields(name), " ") }
