package platform

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA1 secret "12345678901234567890", truncated to 6 digits.
func TestTOTPCodeMatchesRFC6238(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{
		59:          "287082",
		1111111109:  "081804",
		1111111111:  "050471",
		1234567890:  "005924",
		2000000000:  "279037",
		20000000000: "353130",
	} {
		if got := TOTPCode(secret, TOTPStep(time.Unix(unix, 0))); got != want {
			t.Errorf("time %d: got %s, want %s", unix, got, want)
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111111, 0)
	step := TOTPStep(now)

	for name, tc := range map[string]struct {
		code string
		ok   bool
		step int64
	}{
		"current step":   {TOTPCode(secret, step), true, step},
		"previous step":  {TOTPCode(secret, step-1), true, step - 1},
		"next step":      {TOTPCode(secret, step+1), true, step + 1},
		"two steps late": {TOTPCode(secret, step-2), false, 0},
		"wrong code":     {"000000", false, 0},
		"too short":      {"12345", false, 0},
		"empty":          {"", false, 0},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := VerifyTOTP(secret, tc.code, now)
			if ok != tc.ok || got != tc.step {
				t.Fatalf("got (%d, %v), want (%d, %v)", got, ok, tc.step, tc.ok)
			}
		})
	}
}

func TestTOTPSecretRoundTrip(t *testing.T) {
	secret, encoded, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	// Apps show the key in lower case groups of four; it must still parse.
	spaced := strings.ToLower(encoded[:4] + " " + encoded[4:])
	parsed, err := ParseTOTPSecret(spaced)
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed) != string(secret) {
		t.Fatal("secret changed after encoding")
	}
}

func TestParseTOTPSecretRejects(t *testing.T) {
	for name, s := range map[string]string{
		"not base32": "not-base-32!",
		"too short":  "JBSWY3DPEHPK3PXP", // 10 bytes
		"empty":      "",
	} {
		if _, err := ParseTOTPSecret(s); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestTOTPURI(t *testing.T) {
	uri := TOTPURI("Atmosfera", "Console", "ABC")
	if !strings.HasPrefix(uri, "otpauth://totp/Atmosfera:Console?") || !strings.Contains(uri, "secret=ABC") ||
		!strings.Contains(uri, "issuer=Atmosfera") || !strings.Contains(uri, "digits=6") || !strings.Contains(uri, "period=30") {
		t.Fatalf("unexpected uri %s", uri)
	}
}
