package member

import (
	"context"
	"errors"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

// Two tenants share the same system. Everything the repository does must stay inside one of them.
func TestPostgresScopeIsolation(t *testing.T) {
	ctx := context.Background()
	pool := platform.NewTestPool(t)
	repo := NewPostgresRepository(pool)

	id := func(q string, args ...any) string {
		var v string
		if err := pool.QueryRow(ctx, q+" RETURNING id", args...).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	exec := func(q string, args ...any) {
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	system := id(`INSERT INTO systems (code, name) VALUES ('olympus', 'Olympus')`)
	system2 := id(`INSERT INTO systems (code, name) VALUES ('pulso', 'Pulso')`)
	gymA := id(`WITH c AS (INSERT INTO clients (name) VALUES ('Gym A') RETURNING id) INSERT INTO tenants (ruc, legal_name, client_id) SELECT '20111111111', 'Gym A', id FROM c`)
	gymB := id(`WITH c AS (INSERT INTO clients (name) VALUES ('Gym B') RETURNING id) INSERT INTO tenants (ruc, legal_name, client_id) SELECT '20222222222', 'Gym B', id FROM c`)
	platform.SeedRoles(t, pool, system, "dueño", "cajero", "supervisor")
	platform.SeedRoles(t, pool, system2, "cajero")
	for _, ts := range [][2]string{{gymA, system}, {gymB, system}, {gymB, system2}} {
		exec(`INSERT INTO tenant_systems (tenant_id, system_id) VALUES ($1, $2)`, ts[0], ts[1])
	}
	user := func(dni, name string) string {
		return id(`INSERT INTO users (dni, full_name, password_hash) VALUES ($1, $2, 'h')`, dni, name)
	}
	ownerA, cashierA, cashierB, sharedA := user("11111111", "Owner A"), user("22222222", "Cashier A"), user("33333333", "Cashier B"), user("44444444", "Shared")
	grant := func(u, s, t, role string, manage bool) {
		exec(`INSERT INTO access (user_id, system_id, tenant_id, role, manage_users) VALUES ($1, $2, $3, $4, $5)`, u, s, t, role, manage)
	}
	grant(ownerA, system, gymA, "dueño", true)
	grant(cashierA, system, gymA, "cajero", false)
	grant(cashierB, system, gymB, "cajero", false)
	grant(sharedA, system, gymA, "cajero", false)
	grant(sharedA, system2, gymB, "cajero", false) // also works for another organization

	t.Run("list sees only its own tenant", func(t *testing.T) {
		list, err := repo.List(ctx, system, gymA)
		if err != nil || len(list) != 3 {
			t.Fatalf("got %+v err %v", list, err)
		}
		for _, m := range list {
			if m.UserID == cashierB {
				t.Fatal("a member of another tenant leaked into the list")
			}
		}
		if list, _ := repo.List(ctx, system, gymB); len(list) != 1 || list[0].UserID != cashierB {
			t.Fatalf("got %+v", list)
		}
	})

	t.Run("get", func(t *testing.T) {
		m, err := repo.Get(ctx, system, gymA, cashierA)
		if err != nil || m.Role != "cajero" || m.DNI != "22222222" || m.ManageUsers {
			t.Fatalf("got %+v err %v", m, err)
		}
		if _, err := repo.Get(ctx, system, gymA, cashierB); !errors.Is(err, ErrMemberNotFound) {
			t.Fatalf("a member of another tenant must not be visible: %v", err)
		}
	})

	t.Run("cannot change or remove a member of another tenant", func(t *testing.T) {
		if ok, err := repo.UpdateRole(ctx, system, gymA, cashierB, "admin"); err != nil || ok {
			t.Fatalf("update crossed tenants: %v %v", ok, err)
		}
		if ok, err := repo.Remove(ctx, system, gymA, cashierB); err != nil || ok {
			t.Fatalf("remove crossed tenants: %v %v", ok, err)
		}
		if m, _ := repo.Get(ctx, system, gymB, cashierB); m.Role != "cajero" {
			t.Fatalf("victim was modified: %+v", m)
		}
	})

	t.Run("cannot change or remove an owner", func(t *testing.T) {
		if ok, _ := repo.UpdateRole(ctx, system, gymA, ownerA, "cajero"); ok {
			t.Fatal("owner role was changed")
		}
		if ok, _ := repo.Remove(ctx, system, gymA, ownerA); ok {
			t.Fatal("owner was removed")
		}
	})

	t.Run("update and remove inside the tenant", func(t *testing.T) {
		if ok, err := repo.UpdateRole(ctx, system, gymA, cashierA, "supervisor"); err != nil || !ok {
			t.Fatalf("got %v %v", ok, err)
		}
		if m, _ := repo.Get(ctx, system, gymA, cashierA); m.Role != "supervisor" {
			t.Fatalf("got %+v", m)
		}
		if ok, err := repo.Remove(ctx, system, gymA, cashierA); err != nil || !ok {
			t.Fatalf("got %v %v", ok, err)
		}
		if _, err := repo.Get(ctx, system, gymA, cashierA); !errors.Is(err, ErrMemberNotFound) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("only in tenant", func(t *testing.T) {
		if only, err := repo.OnlyInTenant(ctx, ownerA, gymA); err != nil || !only {
			t.Fatalf("got %v %v", only, err)
		}
		if only, _ := repo.OnlyInTenant(ctx, sharedA, gymA); only {
			t.Fatal("a person who also works for another tenant must not count as exclusive")
		}
		if only, _ := repo.OnlyInTenant(ctx, cashierB, gymA); only {
			t.Fatal("a person who belongs to a different tenant is not exclusive to this one")
		}
	})
}
