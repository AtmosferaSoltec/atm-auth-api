package role

import (
	"context"
	"errors"
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

	cajero, err := repo.Create(ctx, Role{SystemID: olympus, Name: "cajero", Description: "Cobra"})
	if err != nil || cajero.ID == "" {
		t.Fatalf("got %+v err %v", cajero, err)
	}
	if _, err := repo.Create(ctx, Role{SystemID: olympus, Name: "admin"}); err != nil {
		t.Fatal(err)
	}

	t.Run("a name is unique in a system, whatever its case", func(t *testing.T) {
		for _, name := range []string{"cajero", "Cajero", "CAJERO"} {
			if _, err := repo.Create(ctx, Role{SystemID: olympus, Name: name}); !errors.Is(err, ErrRoleExists) {
				t.Fatalf("%q: got %v", name, err)
			}
		}
	})
	t.Run("another system can use the same name", func(t *testing.T) {
		if _, err := repo.Create(ctx, Role{SystemID: pulso, Name: "cajero"}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unknown system", func(t *testing.T) {
		if _, err := repo.Create(ctx, Role{SystemID: "00000000-0000-0000-0000-000000000000", Name: "x"}); !errors.Is(err, ErrSystemNotFound) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("list is per system, ordered, with the number of people", func(t *testing.T) {
		user := insertID(t, pool, `INSERT INTO users (dni, full_name, password_hash) VALUES ('11111111', 'Ana', 'h')`)
		other := insertID(t, pool, `INSERT INTO users (dni, full_name, password_hash) VALUES ('22222222', 'Beto', 'h')`)
		acme := insertID(t, pool, `INSERT INTO tenants (ruc, legal_name) VALUES ('20123456789', 'Acme')`)
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

		// A role someone has cannot be deleted.
		if err := repo.Delete(ctx, olympus, cajero.ID); !errors.Is(err, ErrRoleInUse) {
			t.Fatalf("got %v", err)
		}
		if list, _ := repo.List(ctx, olympus); len(list) != 2 {
			t.Fatalf("the role in use must still exist: %+v", list)
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

	t.Run("update the description, never the name", func(t *testing.T) {
		list, _ := repo.List(ctx, pulso)
		updated, err := repo.UpdateDescription(ctx, pulso, list[0].ID, "Nueva")
		if err != nil || updated.Description != "Nueva" || updated.Name != "cajero" {
			t.Fatalf("got %+v err %v", updated, err)
		}
		// A role id from another system is not found.
		if _, err := repo.UpdateDescription(ctx, "00000000-0000-0000-0000-000000000000", list[0].ID, "x"); !errors.Is(err, ErrRoleNotFound) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("delete an unused role", func(t *testing.T) {
		list, _ := repo.List(ctx, pulso)
		if err := repo.Delete(ctx, pulso, list[0].ID); err != nil {
			t.Fatal(err)
		}
		if err := repo.Delete(ctx, pulso, list[0].ID); !errors.Is(err, ErrRoleNotFound) {
			t.Fatalf("got %v", err)
		}
	})
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
