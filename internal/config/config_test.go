package config

import (
	"testing"
	"time"
)

func setRequired(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("ADMIN_USER", "admin")
	t.Setenv("ADMIN_PASSWORD", "a-long-admin-password")
	t.Setenv("JWT_PRIVATE_KEY", "key")
}

func TestLoad(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		setRequired(t)
		t.Setenv("APP_ENV", "")
		t.Setenv("HTTP_ADDR", "")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Env != "development" || cfg.HTTPAddr != ":8080" {
			t.Fatalf("unexpected defaults: %+v", cfg)
		}
		if cfg.AccessTTL != 10*time.Minute || cfg.RefreshTTL != 30*24*time.Hour || cfg.LoginMaxPerSubject != 5 || cfg.LoginWindow != 15*time.Minute {
			t.Fatalf("unexpected session defaults: %+v", cfg)
		}
	})
	t.Run("missing database url", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "")
		if _, err := Load(); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("invalid env", func(t *testing.T) {
		setRequired(t)
		t.Setenv("APP_ENV", "staging")
		if _, err := Load(); err == nil {
			t.Fatal("expected error")
		}
	})
	for _, name := range []string{"ADMIN_USER", "ADMIN_PASSWORD", "JWT_PRIVATE_KEY"} {
		t.Run("missing "+name, func(t *testing.T) {
			setRequired(t)
			t.Setenv(name, "")
			if _, err := Load(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	t.Run("short admin password", func(t *testing.T) {
		setRequired(t)
		t.Setenv("ADMIN_PASSWORD", "short-11-ch")
		if _, err := Load(); err == nil {
			t.Fatal("a password under 12 characters must be refused")
		}
		t.Setenv("ADMIN_PASSWORD", "exactly-12-c")
		if _, err := Load(); err != nil {
			t.Fatalf("12 characters must be accepted: %v", err)
		}
	})
	t.Run("custom durations", func(t *testing.T) {
		setRequired(t)
		t.Setenv("ACCESS_TOKEN_TTL", "5m")
		cfg, err := Load()
		if err != nil || cfg.AccessTTL != 5*time.Minute {
			t.Fatalf("got %v %v", cfg.AccessTTL, err)
		}
	})
}
