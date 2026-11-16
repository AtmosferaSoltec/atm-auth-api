// Command totpsetup creates the superadmin's second factor (a 6-digit code that changes every 30 seconds).
//
// It prints a new secret for ADMIN_TOTP_SECRET and the otpauth:// link that authenticator apps read. Add it to
// the app (Apple Passwords: Edit > Set Up Verification Code > Enter Setup Key, and paste the setup key), then
// confirm it works by passing the secret and the code the app shows:
//
//	totpsetup                      # new secret
//	totpsetup -check SECRET 123456 # does the app show the right code?
//
// The output is a secret: never paste it in a chat, ticket or log.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

const (
	issuer  = "Atmosfera Console"
	account = "superadmin"
)

func main() {
	if len(os.Args) == 4 && os.Args[1] == "-check" {
		os.Exit(check(os.Args[2], os.Args[3]))
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: totpsetup | totpsetup -check SECRET CODE")
		os.Exit(2)
	}
	_, encoded, err := platform.NewTOTPSecret()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Println("ADMIN_TOTP_SECRET=" + encoded)
	fmt.Println()
	fmt.Println("Setup key (type it in the authenticator app):", encoded)
	fmt.Println("Link (or turn it into a QR code locally):    ", platform.TOTPURI(issuer, account, encoded))
}

func check(secret, code string) int {
	key, err := platform.ParseTOTPSecret(secret)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if _, ok := platform.VerifyTOTP(key, code, time.Now()); !ok {
		fmt.Println("The code does not match. Check the setup key and that the clock of this machine and the phone are right.")
		return 1
	}
	fmt.Println("The code matches.")
	return 0
}
