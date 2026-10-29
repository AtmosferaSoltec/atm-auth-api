package platform

import (
	"context"
	"os"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewTestPool returns a pool on a freshly migrated, empty schema.
// It skips the test when TEST_DATABASE_URL is not set. The target database is wiped.
func NewTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := NewPool(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool, migrations.Files); err != nil {
		t.Fatal(err)
	}
	return pool
}

// SeedRoles adds role names to the catalog of a system, so tests can give them to people.
func SeedRoles(t *testing.T, pool *pgxpool.Pool, systemID string, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO system_roles (system_id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING`, systemID, name); err != nil {
			t.Fatal(err)
		}
	}
}
