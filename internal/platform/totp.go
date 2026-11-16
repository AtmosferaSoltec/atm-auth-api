package platform

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP (RFC 6238) with the parameters every authenticator app supports: HMAC-SHA1, 6 digits, 30-second steps.
const (
	TOTPDigits = 6
	TOTPPeriod = 30 * time.Second
	// totpSkew is how many steps before and after the current one are accepted, for clocks that drift a little.
	totpSkew = 1
	// MinTOTPSecretBytes is the shortest secret accepted (128 bits); new secrets have 160 bits, as RFC 4226 recommends.
	MinTOTPSecretBytes = 16
	newTOTPSecretBytes = 20
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random secret and its base32 form, the one authenticator apps take as "setup key".
func NewTOTPSecret() ([]byte, string, error) {
	secret := make([]byte, newTOTPSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return nil, "", fmt.Errorf("new totp secret: %w", err)
	}
	return secret, totpEncoding.EncodeToString(secret), nil
}

// ParseTOTPSecret decodes a base32 secret. Spaces, dashes, padding and lower case are tolerated.
func ParseTOTPSecret(s string) ([]byte, error) {
	clean := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(s))
	secret, err := totpEncoding.DecodeString(clean)
	if err != nil {
		return nil, errors.New("totp secret is not valid base32")
	}
	if len(secret) < MinTOTPSecretBytes {
		return nil, fmt.Errorf("totp secret must have at least %d bytes", MinTOTPSecretBytes)
	}
	return secret, nil
}

// TOTPURI builds the otpauth:// link that authenticator apps read from a QR code.
func TOTPURI(issuer, account, encodedSecret string) string {
	q := url.Values{}
	q.Set("secret", encodedSecret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(TOTPDigits))
	q.Set("period", fmt.Sprint(int(TOTPPeriod.Seconds())))
	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// TOTPStep is the time step a moment falls in.
func TOTPStep(t time.Time) int64 {
	return t.Unix() / int64(TOTPPeriod.Seconds())
}

// TOTPCode returns the code of one step.
func TOTPCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", TOTPDigits, value%1_000_000)
}

// VerifyTOTP checks a code against the steps around t and returns the step it matched.
// Every candidate is compared, in constant time, so the time taken does not depend on which step matched.
func VerifyTOTP(secret []byte, code string, t time.Time) (int64, bool) {
	if len(code) != TOTPDigits {
		return 0, false
	}
	current := TOTPStep(t)
	var matched int64
	found := 0
	for step := current - totpSkew; step <= current+totpSkew; step++ {
		eq := subtle.ConstantTimeCompare([]byte(TOTPCode(secret, step)), []byte(code))
		if eq == 1 && found == 0 {
			matched = step
		}
		found |= eq
	}
	return matched, found == 1
}
