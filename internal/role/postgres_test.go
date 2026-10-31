package role

import (
	"context"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
	"github.com/jackc/pgx/v5/pgxpool"
)

func insertID(t *testing.T, pool *pgxpool.Pool, query string, args ...any) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), query+" RETURNING id", args...).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPostgresRepository(t *testing.T) {
	ctx := context.Background()
	pool := platform.NewTestPool(t)
	repo := NewPostgresRepository(pool)

	olympus := insertID(t, pool, `INSERT INTO systems (code, name) VALUES ('olympus', 'Olympus')`)
	pulso := insertID(t, pool, `INSERT INTO systems (code, name) VALUES ('pulso', 'Pulso')`)

	platform.SeedRoles(t, pool, olympus, "admin", "cajero")
	platform.SeedRoles(t, pool, pulso, "cajero")

	t.Run("list is per system, ordered, with the number of people", func(t *testing.T) {
		user := insertID(t, pool, `INSERT INTO users (dni, full_name, password_hash) VALUES ('11111111', 'Ana', 'h')`)
		other := insertID(t, pool, `INSERT INTO users (dni, full_name, password_hash) VALUES ('22222222', 'Beto', 'h')`)
		acme := insertID(t, pool, `WITH c AS (INSERT INTO clients (name) VALUES ('Acme') RETURNING id) INSERT INTO tenants (ruc, legal_name, client_id) SELECT '20123456789', 'Acme', id FROM c`)
		if _, err := pool.Exec(ctx, `INSERT INTO tenant_systems (tenant_id, system_id) VALUES ($1, $2)`, acme, olympus); err != nil {
			t.Fatal(err)
		}
		for _, u := range []string{user, other} {
			if _, err := pool.Exec(ctx, `INSERT INTO access (user_id, system_id, tenant_id, role) VALUES ($1, $2, $3, 'cajero')`, u, olympus, acme); err != nil {
				t.Fatal(err)
			}
		}
		list, err := repo.List(ctx, olympus)
		if err != nil || len(list) != 2 || list[0].Name != "admin" || list[0].Users != 0 || list[1].Name != "cajero" || list[1].Users != 2 {
			t.Fatalf("got %+v err %v", list, err)
		}
		if list, _ := repo.List(ctx, pulso); len(list) != 1 || list[0].Users != 0 {
			t.Fatalf("pulso must not count olympus accesses: %+v", list)
		}

		// The accesses keep pointing at the catalog: removing the system takes both away in one go.
		if _, err := pool.Exec(ctx, `DELETE FROM systems WHERE id = $1`, olympus); err != nil {
			t.Fatalf("deleting a whole system must not be blocked by its roles: %v", err)
		}
		var left int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM access) + (SELECT count(*) FROM system_roles WHERE system_id = $1)`, olympus).Scan(&left); err != nil || left != 0 {
			t.Fatalf("left over: %d err %v", left, err)
		}
	})
}

func TestListShowsRetiredRoles(t *testing.T) {
	ctx := context.Background()
	pool := platform.NewTestPool(t)
	system := insertID(t, pool, `INSERT INTO systems (code, name) VALUES ('olympus', 'Olympus')`)
	platform.SeedRoles(t, pool, system, "admin", "old")
	if _, err := pool.Exec(ctx, `UPDATE system_roles SET active = false WHERE name = 'old'`); err != nil {
		t.Fatal(err)
	}
	list, err := NewPostgresRepository(pool).List(ctx, system)
	if err != nil || len(list) != 2 || !list[0].Active || list[1].Name != "old" || list[1].Active {
		t.Fatalf("got %+v err %v", list, err)
	}
}

func TestMigrationKeepsRolesAlreadyInUse(t *testing.T) {
	// Fresh databases have no accesses, so what is checked here is the catalog shape the migration builds on.
	ctx := context.Background()
	pool := platform.NewTestPool(t)
	system := insertID(t, pool, `INSERT INTO systems (code, name) VALUES ('olympus', 'Olympus')`)
	if _, err := pool.Exec(ctx, `INSERT INTO system_roles (system_id, name) VALUES ($1, 'a'), ($1, 'a')`, system); err == nil {
		t.Fatal("the database must refuse a repeated role in a system")
	}
}
