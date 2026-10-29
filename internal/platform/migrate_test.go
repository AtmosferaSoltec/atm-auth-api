package platform

import (
	"context"
	"io/fs"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/migrations"
)

func TestMigrateIsIdempotent(t *testing.T) {
	pool := NewTestPool(t) // already migrated once
	ctx := context.Background()
	if err := Migrate(ctx, pool, migrations.Files); err != nil {
		t.Fatalf("second run failed: %v", err)
	}
	files, _ := fs.Glob(migrations.Files, "*.sql")
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&n); err != nil || n != len(files) {
		t.Fatalf("recorded migrations = %d, want %d, err %v", n, len(files), err)
	}
}
