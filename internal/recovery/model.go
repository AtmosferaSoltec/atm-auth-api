// Package recovery lets a person who forgot their password set a new one with a code sent to their email.
// The same flow sets a first password for accounts created with Google.
package recovery

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"regexp"
	"time"
)

const (
	// CodeTTL is how long a code works.
	CodeTTL = 15 * time.Minute
	// MaxCodeAttempts: at the fifth wrong guess the code stops working.
	MaxCodeAttempts = 5
	// MaxSends is how many codes one account may be sent per SendWindow.
	MaxSends   = 3
	SendWindow = 24 * time.Hour

	MinPasswordLength = 8
	MaxPasswordLength = 128
)

var (
	codePattern   = regexp.MustCompile(`^[0-9]{6}$`)
	systemPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
)

// newCode returns 6 digits from a cryptographic generator.
func newCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("generate reset code: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// DeriveKey takes from the server secret a key of its own for the codes.
func DeriveKey(secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("atm-auth-api/password-reset-codes/v1"))
	return mac.Sum(nil)
}

// hashCode is the HMAC-SHA256 of the code, bound to the user.
func hashCode(key []byte, userID, code string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(userID))
	mac.Write([]byte{0})
	mac.Write([]byte(code))
	return mac.Sum(nil)
}
