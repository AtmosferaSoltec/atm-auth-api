package catalog

import (
	"context"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

func TestCatalogDeclaration(t *testing.T) {
	want := map[string][]string{
		"pulso": {"admin", "receptionist"}, "lavendimia": {"admin", "cashier"},
		"nova": {"admin", "receptionist", "cashier", "dentist"}, "orbita": {"admin"}, "olympuscourier": {"admin", "user", "delivery"},
	}
	if len(Systems) != len(want) {
		t.Fatalf("got %d systems", len(Systems))
	}
	for _, s := range Systems {
		names := map[string]bool{}
		for _, r := range s.Roles {
			if names[r.Name] {
				t.Fatalf("%s repeats role %s", s.Code, r.Name)
			}
			names[r.Name] = true
		}
		if len(names) != len(want[s.Code]) {
			t.Fatalf("%s roles %v, want %v", s.Code, names, want[s.Code])
		}
		for _, n := range want[s.Code] {
			if !names[n] {
				t.Fatalf("%s lacks role %s", s.Code, n)
			}
		}
	}
}

func TestSyncIsIdempotentAndReportsWithoutDeleting(t *testing.T) {
	ctx := context.Background()
	pool := platform.NewTestPool(t)
	svc := NewService(NewPostgresRepository(pool), Systems)

	// A system and a role outside the catalog, one of them in use, plus a customized catalog system.
	if _, err := pool.Exec(ctx, `INSERT INTO systems (code, name, session_mode, secret_hash) VALUES ('legacy', 'Legacy', 'persistent', 'h'), ('pulso', 'Mi Pulso', 'temporary', 'h')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO system_roles (system_id, name, description) SELECT id, 'boss', '' FROM systems WHERE code IN ('legacy', 'pulso')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO system_roles (system_id, name, description) SELECT id, 'admin', 'old' FROM systems WHERE code = 'pulso'`); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		orphans, err := svc.Sync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(orphans.Systems) != 1 || orphans.Systems[0] != "legacy" {
			t.Fatalf("orphan systems: %+v", orphans)
		}
		if len(orphans.Roles) != 2 || orphans.Roles[0].SystemCode != "legacy" || orphans.Roles[1].SystemCode != "pulso" || orphans.Roles[1].Name != "boss" {
			t.Fatalf("orphan roles: %+v", orphans)
		}
	}

	var systems, roles int
	var name, mode, desc string
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM systems), (SELECT count(*) FROM system_roles),
		(SELECT name FROM systems WHERE code = 'pulso'), (SELECT session_mode FROM systems WHERE code = 'pulso'),
		(SELECT r.description FROM system_roles r JOIN systems s ON s.id = r.system_id WHERE s.code = 'pulso' AND r.name = 'admin')`).
		Scan(&systems, &roles, &name, &mode, &desc); err != nil {
		t.Fatal(err)
	}
	// 6 systems (legacy stays); roles: pulso 2 + boss, lavendimia 2, nova 4, orbita 1, olympus 3, legacy boss = 14.
	if systems != 6 || roles != 14 {
		t.Fatalf("systems %d roles %d", systems, roles)
	}
	if name != "Mi Pulso" || mode != "temporary" {
		t.Fatalf("an existing system must keep what the console set: %s %s", name, mode)
	}
	if desc == "old" {
		t.Fatal("a role description follows the catalog")
	}
}

func TestSyncRetiresRolesOutsideTheCatalogAndReactivatesThem(t *testing.T) {
	ctx := context.Background()
	pool := platform.NewTestPool(t)

	// Nova exists with its old admin role, plus a leftover role and a leftover system.
	if _, err := pool.Exec(ctx, `INSERT INTO systems (code, name) VALUES ('nova', 'Nova'), ('legacy', 'Legacy')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO system_roles (system_id, name) SELECT id, r FROM systems, unnest(ARRAY['admin', 'boss']) r WHERE code = 'nova'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO system_roles (system_id, name) SELECT id, 'x' FROM systems WHERE code = 'legacy'`); err != nil {
		t.Fatal(err)
	}
	active := func(system, role string) bool {
		var a bool
		if err := pool.QueryRow(ctx, `SELECT r.active FROM system_roles r JOIN systems s ON s.id = r.system_id WHERE s.code = $1 AND r.name = $2`, system, role).Scan(&a); err != nil {
			t.Fatal(err)
		}
		return a
	}

	svc := NewService(NewPostgresRepository(pool), Systems)
	for i := 0; i < 2; i++ {
		if _, err := svc.Sync(ctx); err != nil {
			t.Fatal(err)
		}
		if !active("nova", "admin") || !active("nova", "dentist") || active("nova", "boss") || active("legacy", "x") {
			t.Fatalf("run %d: catalog roles must be active and leftovers inactive", i)
		}
	}

	// A role that comes back to the catalog is reactivated; one that leaves is retired without deleting its access.
	trimmed := []System{{Code: "nova", Name: "Nova", Roles: []Role{{Name: "admin"}}}}
	if _, err := NewService(NewPostgresRepository(pool), trimmed).Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if active("nova", "dentist") {
		t.Fatal("a role removed from the catalog must be retired")
	}
	if _, err := svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if !active("nova", "dentist") {
		t.Fatal("a role back in the catalog must be reactivated")
	}
}
