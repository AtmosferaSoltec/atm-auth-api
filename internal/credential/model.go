package credential

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

const secretPrefix = "atm_"

// Credential is what the service stores about a system's secret. The secret itself is never stored.
type Credential struct {
	SystemID   string
	Code       string
	SecretHash string
	Active     bool
}

// Issued is a new secret, shown to the caller once.
type Issued struct {
	// ClientID is the system code.
	ClientID     string
	ClientSecret string
}

func newSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return secretPrefix + hex.EncodeToString(raw), nil
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
