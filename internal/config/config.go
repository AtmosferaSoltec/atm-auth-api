package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// MinAdminPasswordLength is the shortest superadmin password accepted: the whole team shares it.
const MinAdminPasswordLength = 12

// Argon2 holds the argon2id cost parameters.
type Argon2 struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

type Config struct {
	Env         string
	HTTPAddr    string
	DatabaseURL string
	Argon2      Argon2

	// AdminUser and AdminPassword are the superadmin credentials. The password is hashed once at startup;
	// only the hash is kept in memory.
	AdminUser     string
	AdminPassword string

	JWTPrivateKey string
	JWTIssuer     string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	// TemporaryRefreshTTL bounds the session of systems that do not remember their users.
	TemporaryRefreshTTL time.Duration

	LoginMaxPerSubject int
	LoginMaxPerIP      int
	LoginWindow        time.Duration
	ClientIPHeader     string
}

// Argon2FromEnv reads ARGON2_MEMORY_KIB, ARGON2_TIME and ARGON2_THREADS, falling back to the OWASP minimums.
func Argon2FromEnv() Argon2 {
	return Argon2{
		MemoryKiB: uint32(getenvInt("ARGON2_MEMORY_KIB", 19456)),
		Time:      uint32(getenvInt("ARGON2_TIME", 2)),
		Threads:   uint8(getenvInt("ARGON2_THREADS", 1)),
	}
}

// Load reads the configuration from environment variables.
func Load() (Config, error) {
	cfg := Config{
		Env:         getenv("APP_ENV", "development"),
		HTTPAddr:    getenv("HTTP_ADDR", ":8080"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		Argon2:      Argon2FromEnv(),

		AdminUser:     os.Getenv("ADMIN_USER"),
		AdminPassword: os.Getenv("ADMIN_PASSWORD"),

		JWTPrivateKey:       os.Getenv("JWT_PRIVATE_KEY"),
		JWTIssuer:           getenv("JWT_ISSUER", "atm-auth-api"),
		AccessTTL:           getenvDuration("ACCESS_TOKEN_TTL", 10*time.Minute),
		RefreshTTL:          getenvDuration("REFRESH_TOKEN_TTL", 90*24*time.Hour),
		TemporaryRefreshTTL: getenvDuration("TEMPORARY_REFRESH_TTL", 12*time.Hour),

		LoginMaxPerSubject: getenvInt("LOGIN_MAX_ATTEMPTS", 5),
		LoginMaxPerIP:      getenvInt("LOGIN_MAX_ATTEMPTS_PER_IP", 20),
		LoginWindow:        getenvDuration("LOGIN_WINDOW", 15*time.Minute),
		ClientIPHeader:     os.Getenv("CLIENT_IP_HEADER"),
	}
	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("load config: DATABASE_URL is required")
	}
	for name, v := range map[string]string{
		"ADMIN_USER": cfg.AdminUser, "ADMIN_PASSWORD": cfg.AdminPassword, "JWT_PRIVATE_KEY": cfg.JWTPrivateKey,
	} {
		if v == "" {
			return Config{}, fmt.Errorf("load config: %s is required", name)
		}
	}
	if len(cfg.AdminPassword) < MinAdminPasswordLength {
		return Config{}, fmt.Errorf("load config: ADMIN_PASSWORD must have at least %d characters", MinAdminPasswordLength)
	}
	if cfg.Env != "development" && cfg.Env != "production" {
		return Config{}, fmt.Errorf("load config: invalid APP_ENV %q", cfg.Env)
	}
	return cfg, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return fallback
}

func getenvDuration(key string, fallback time.Duration) time.Duration {
	if d, err := time.ParseDuration(os.Getenv(key)); err == nil && d > 0 {
		return d
	}
	return fallback
}
