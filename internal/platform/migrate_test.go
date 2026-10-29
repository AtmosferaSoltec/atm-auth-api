package platform

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"

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

// Production already holds accesses with free-text roles when the role catalog arrives: they must
// become catalog roles and keep working, and the same text in two systems must give two roles.
func TestRoleCatalogMigrationKeepsExistingAccesses(t *testing.T) {
	pool := NewTestPool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public"); err != nil {
		t.Fatal(err)
	}

	// The schema as it was before the catalog.
	before := fstest.MapFS{}
	all, _ := fs.Glob(migrations.Files, "*.sql")
	for _, name := range all {
		if name < "0007" {
			data, _ := fs.ReadFile(migrations.Files, name)
			before[name] = &fstest.MapFile{Data: data}
		}
	}
	if err := Migrate(ctx, pool, before); err != nil {
		t.Fatal(err)
	}

	id := func(q string, args ...any) string {
		t.Helper()
		var v string
		if err := pool.QueryRow(ctx, q+" RETURNING id", args...).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	olympus := id(`INSERT INTO systems (code, name) VALUES ('olympus', 'Olympus')`)
	pulso := id(`INSERT INTO systems (code, name) VALUES ('pulso', 'Pulso')`)
	acme := id(`INSERT INTO tenants (ruc, legal_name) VALUES ('20123456789', 'Acme')`)
	for _, sys := range []string{olympus, pulso} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenant_systems (tenant_id, system_id) VALUES ($1, $2)`, acme, sys); err != nil {
			t.Fatal(err)
		}
	}
	users := map[string]string{}
	for _, grant := range []struct{ dni, system, role string }{
		{"11111111", olympus, "cajero"}, {"22222222", olympus, "cajero"}, {"33333333", olympus, "admin"}, {"11111111", pulso, "cajero"},
	} {
		if _, ok := users[grant.dni]; !ok {
			users[grant.dni] = id(`INSERT INTO users (dni, full_name, password_hash) VALUES ($1, 'Persona', 'h')`, grant.dni)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO access (user_id, system_id, tenant_id, role) VALUES ($1, $2, $3, $4)`, users[grant.dni], grant.system, acme, grant.role); err != nil {
			t.Fatal(err)
		}
	}

	if err := Migrate(ctx, pool, migrations.Files); err != nil {
		t.Fatalf("the catalog migration failed on existing data: %v", err)
	}

	var roles, accesses int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM system_roles), (SELECT count(*) FROM access)`).Scan(&roles, &accesses); err != nil {
		t.Fatal(err)
	}
	// olympus: cajero + admin; pulso: cajero. Nobody lost their access.
	if roles != 3 || accesses != 4 {
		t.Fatalf("roles=%d accesses=%d, want 3 and 4", roles, accesses)
	}
	// From now on the catalog is enforced.
	if _, err := pool.Exec(ctx, `UPDATE access SET role = 'inventado' WHERE system_id = $1`, olympus); err == nil {
		t.Fatal("an access must not point at a role outside the catalog")
	}
}
