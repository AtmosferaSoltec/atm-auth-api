// Command hashpw prints an argon2id hash of the password read from stdin.
// Use it to produce the value of ADMIN_PASSWORD_HASH.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/config"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

func main() {
	fmt.Fprint(os.Stderr, "Password: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(os.Stderr, "error: could not read password")
		os.Exit(1)
	}
	password := strings.TrimRight(line, "\r\n")
	if len(password) < 12 {
		fmt.Fprintln(os.Stderr, "error: password must have at least 12 characters")
		os.Exit(1)
	}
	hash, err := platform.NewPasswordHasher(platform.Argon2Params(config.Argon2FromEnv())).Hash(password)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Println(hash)
}
