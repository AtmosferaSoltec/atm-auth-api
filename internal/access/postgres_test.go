package access

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
	"github.com/jackc/pgx/v5/pgxpool"
)

type world struct {
	pool           *pgxpool.Pool
	user, other    string
	olympus, pulso string
	acme, globex   string
}

func insertID(t *testing.T, pool *pgxpool.Pool, query string, args ...any) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), query+" RETURNING id", args...).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func newWorld(t *testing.T) world {
	t.Helper()
	pool := platform.NewTestPool(t)
	w := world{pool: pool}
	w.user = insertID(t, pool, `INSERT INTO users (dni, full_name, password_hash) VALUES ('11111111', 'Ana', 'h')`)
	w.other = insertID(t, pool, `INSERT INTO users (dni, full_name, password_hash) VALUES ('22222222', 'Beto', 'h')`)
	w.olympus = insertID(t, pool, `INSERT INTO systems (code, name) VALUES ('olympus', 'Olympus')`)
	w.pulso = insertID(t, pool, `INSERT INTO systems (code, name) VALUES ('pulso', 'Pulso')`)
	w.acme = insertID(t, pool, `WITH c AS (INSERT INTO clients (name) VALUES ('Acme') RETURNING id) INSERT INTO tenants (ruc, legal_name, client_id) SELECT '20123456789', 'Acme', id FROM c`)
	w.globex = insertID(t, pool, `WITH c AS (INSERT INTO clients (name) VALUES ('Globex') RETURNING id) INSERT INTO tenants (ruc, legal_name, client_id) SELECT '20987654321', 'Globex', id FROM c`)
	for _, sys := range []string{w.olympus, w.pulso} {
		platform.SeedRoles(t, pool, sys, "cajero", "admin", "dueño", "x", "otro")
	}
	for _, ts := range [][2]string{{w.acme, w.olympus}, {w.acme, w.pulso}, {w.globex, w.pulso}} {
		if _, err := pool.Exec(context.Background(), `INSERT INTO tenant_systems (tenant_id, system_id) VALUES ($1, $2)`, ts[0], ts[1]); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

func TestAssignRules(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	repo := NewPostgresRepository(w.pool)

	a, err := repo.Assign(ctx, Access{UserID: w.user, SystemID: w.olympus, TenantID: w.acme, Role: "cajero"})
	if err != nil || a.ID == "" {
		t.Fatalf("got %+v err %v", a, err)
	}

	// The same person in the same company of the same system twice is rejected.
	if _, err := repo.Assign(ctx, Access{UserID: w.user, SystemID: w.olympus, TenantID: w.acme, Role: "x"}); !errors.Is(err, ErrUserAlreadyInSystem) {
		t.Fatalf("got %v", err)
	}
	// The same user can be in a different system, with a different tenant.
	if _, err := repo.Assign(ctx, Access{UserID: w.user, SystemID: w.pulso, TenantID: w.globex, Role: "admin"}); err != nil {
		t.Fatalf("different system must be allowed: %v", err)
	}
	// The tenant has not contracted that system.
	if _, err := repo.Assign(ctx, Access{UserID: w.other, SystemID: w.olympus, TenantID: w.globex, Role: "x"}); !errors.Is(err, ErrSystemNotEnabled) {
		t.Fatalf("got %v", err)
	}
	if _, err := repo.Assign(ctx, Access{UserID: "00000000-0000-0000-0000-000000000000", SystemID: w.olympus, TenantID: w.acme, Role: "x"}); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("got %v", err)
	}

	if err := repo.Remove(ctx, w.user, w.pulso); err != nil {
		t.Fatal(err)
	}
	if err := repo.Remove(ctx, w.user, w.pulso); !errors.Is(err, ErrAccessNotFound) {
		t.Fatalf("got %v", err)
	}
	if _, err := repo.Assign(ctx, Access{UserID: w.user, SystemID: w.pulso, TenantID: w.acme, Role: "admin"}); err != nil {
		t.Fatalf("assign after leaving: %v", err)
	}
}

// A person can work for several companies in the same system.
func TestSeveralCompaniesInOneSystem(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	repo := NewPostgresRepository(w.pool)

	first, err := repo.Assign(ctx, Access{UserID: w.user, SystemID: w.pulso, TenantID: w.acme, Role: "admin", ManageUsers: true})
	if err != nil {
		t.Fatal(err)
	}
	second, err := repo.Assign(ctx, Access{UserID: w.user, SystemID: w.pulso, TenantID: w.globex, Role: "dueño"})
	if err != nil {
		t.Fatalf("a second company in the same system must be allowed: %v", err)
	}

	t.Run("without a choice it enters the first company they were given", func(t *testing.T) {
		g, err := repo.Resolve(ctx, w.user, "pulso", "")
		if err != nil || g.TenantID != w.acme {
			t.Fatalf("got %+v err %v", g, err)
		}
	})

	t.Run("a company can be asked for, with the role they have there", func(t *testing.T) {
		g, err := repo.Resolve(ctx, w.user, "pulso", w.globex)
		if err != nil || g.TenantID != w.globex || g.Role != "dueño" || g.ManageUsers {
			t.Fatalf("got %+v err %v", g, err)
		}
		if _, err := repo.Resolve(ctx, w.user, "pulso", "00000000-0000-0000-0000-000000000000"); !errors.Is(err, ErrNoAccess) {
			t.Fatalf("got %v", err)
		}
		// Another person's company is not theirs.
		if _, err := repo.Resolve(ctx, w.other, "pulso", w.globex); !errors.Is(err, ErrNoAccess) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("the company used last is the one login enters", func(t *testing.T) {
		if err := repo.MarkUsed(ctx, w.user, w.pulso, w.globex); err != nil {
			t.Fatal(err)
		}
		g, err := repo.Resolve(ctx, w.user, "pulso", "")
		if err != nil || g.TenantID != w.globex {
			t.Fatalf("got %+v err %v", g, err)
		}
		if err := repo.MarkUsed(ctx, w.user, w.pulso, w.acme); err != nil {
			t.Fatal(err)
		}
		if g, _ := repo.Resolve(ctx, w.user, "pulso", ""); g.TenantID != w.acme {
			t.Fatalf("got %+v", g)
		}
	})

	t.Run("options list the active companies by name", func(t *testing.T) {
		options, err := repo.Options(ctx, w.user, "pulso")
		if err != nil || len(options) != 2 || options[0].Name != "Acme" || options[1].Name != "Globex" || options[0].RUC != "20123456789" || options[0].Role != "admin" || options[1].Role != "dueño" {
			t.Fatalf("got %+v err %v", options, err)
		}
		if _, err := w.pool.Exec(ctx, `UPDATE tenants SET status = 'disabled' WHERE id = $1`, w.globex); err != nil {
			t.Fatal(err)
		}
		if options, _ := repo.Options(ctx, w.user, "pulso"); len(options) != 1 || options[0].Name != "Acme" {
			t.Fatalf("a disabled company must not be offered: %+v", options)
		}
		if _, err := w.pool.Exec(ctx, `UPDATE tenants SET status = 'active' WHERE id = $1`, w.globex); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("one access can be removed without touching the other", func(t *testing.T) {
		if err := repo.RemoveByID(ctx, second.ID); err != nil {
			t.Fatal(err)
		}
		if err := repo.RemoveByID(ctx, second.ID); !errors.Is(err, ErrAccessNotFound) {
			t.Fatalf("got %v", err)
		}
		if g, err := repo.Resolve(ctx, w.user, "pulso", ""); err != nil || g.TenantID != w.acme {
			t.Fatalf("the other company was removed too: %+v err %v", g, err)
		}
		_ = first
	})
}

func TestResolve(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	repo := NewPostgresRepository(w.pool)
	if _, err := repo.Assign(ctx, Access{UserID: w.user, SystemID: w.olympus, TenantID: w.acme, Role: "cajero"}); err != nil {
		t.Fatal(err)
	}

	g, err := repo.Resolve(ctx, w.user, "olympus", "")
	if err != nil || g.TenantID != w.acme || g.Role != "cajero" || g.SystemCode != "olympus" || g.SystemID != w.olympus || g.ManageUsers {
		t.Fatalf("got %+v err %v", g, err)
	}
	for name, args := range map[string][2]string{
		"other system":   {w.user, "pulso"},
		"unknown system": {w.user, "nope"},
		"other user":     {w.other, "olympus"},
	} {
		if _, err := repo.Resolve(ctx, args[0], args[1], ""); !errors.Is(err, ErrNoAccess) {
			t.Fatalf("%s: got %v", name, err)
		}
	}

	// Each switch that deactivates something along the path must remove the access.
	for name, stmt := range map[string]string{
		"system disabled":        `UPDATE systems SET status = 'disabled' WHERE id = '%s'`,
		"tenant disabled":        `UPDATE tenants SET status = 'disabled' WHERE id = '%s'`,
		"tenant system disabled": `UPDATE tenant_systems SET status = 'disabled' WHERE tenant_id = '%s'`,
	} {
		t.Run(name, func(t *testing.T) {
			id := map[string]string{"system disabled": w.olympus, "tenant disabled": w.acme, "tenant system disabled": w.acme}[name]
			sql := strings.Replace(stmt, "%s", id, 1)
			if _, err := w.pool.Exec(ctx, sql); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.Resolve(ctx, w.user, "olympus", ""); !errors.Is(err, ErrNoAccess) {
				t.Fatalf("got %v", err)
			}
			reset := map[string]string{
				"system disabled":        `UPDATE systems SET status = 'active'`,
				"tenant disabled":        `UPDATE tenants SET status = 'active'`,
				"tenant system disabled": `UPDATE tenant_systems SET status = 'active'`,
			}[name]
			if _, err := w.pool.Exec(ctx, reset); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.Resolve(ctx, w.user, "olympus", ""); err != nil {
				t.Fatalf("access must return once re-enabled: %v", err)
			}
		})
	}
}

func TestManageUsersAndListByUser(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	repo := NewPostgresRepository(w.pool)
	if _, err := repo.Assign(ctx, Access{UserID: w.user, SystemID: w.olympus, TenantID: w.acme, Role: "dueño", ManageUsers: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Assign(ctx, Access{UserID: w.user, SystemID: w.pulso, TenantID: w.globex, Role: "cajero"}); err != nil {
		t.Fatal(err)
	}
	if g, _ := repo.Resolve(ctx, w.user, "olympus", ""); !g.ManageUsers {
		t.Fatalf("manage_users lost: %+v", g)
	}
	if g, _ := repo.Resolve(ctx, w.user, "pulso", ""); g.ManageUsers {
		t.Fatalf("manage_users must default to false: %+v", g)
	}

	list, err := repo.ListByUser(ctx, w.user)
	if err != nil || len(list) != 2 || list[0].SystemCode != "olympus" || list[0].TenantName != "Acme" || !list[0].ManageUsers {
		t.Fatalf("got %+v err %v", list, err)
	}
	if list[0].SystemName != "Olympus" {
		t.Fatalf("missing system name: %+v", list[0])
	}
	if list, _ := repo.ListByUser(ctx, w.other); len(list) != 0 {
		t.Fatalf("got %+v", list)
	}
}

func TestAssignNeedsARoleOfTheSystem(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	repo := NewPostgresRepository(w.pool)

	if _, err := repo.Assign(ctx, Access{UserID: w.user, SystemID: w.olympus, TenantID: w.acme, Role: "inventado"}); !errors.Is(err, ErrUnknownRole) {
		t.Fatalf("a role outside the catalog must be refused: %v", err)
	}
	// Roles belong to one system: a role of pulso does not exist in olympus.
	platform.SeedRoles(t, w.pool, w.pulso, "solo-pulso")
	if _, err := repo.Assign(ctx, Access{UserID: w.user, SystemID: w.olympus, TenantID: w.acme, Role: "solo-pulso"}); !errors.Is(err, ErrUnknownRole) {
		t.Fatalf("got %v", err)
	}
	if _, err := repo.Assign(ctx, Access{UserID: w.user, SystemID: w.pulso, TenantID: w.acme, Role: "solo-pulso"}); err != nil {
		t.Fatalf("the role exists in its own system: %v", err)
	}
	// The role is matched exactly: the catalog decides the spelling.
	if _, err := repo.Assign(ctx, Access{UserID: w.other, SystemID: w.pulso, TenantID: w.acme, Role: "Solo-Pulso"}); !errors.Is(err, ErrUnknownRole) {
		t.Fatalf("got %v", err)
	}
}

func TestResolveCarriesSessionPolicyAndIdentity(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	repo := NewPostgresRepository(w.pool)
	if _, err := repo.Assign(ctx, Access{UserID: w.user, SystemID: w.olympus, TenantID: w.acme, Role: "cajero"}); err != nil {
		t.Fatal(err)
	}
	g, err := repo.Resolve(ctx, w.user, "olympus", "")
	if err != nil || g.SessionMode != "persistent" {
		t.Fatalf("default policy: %+v err %v", g, err)
	}
	// The grant says who is signing in and for which company, so the system can link its own records.
	if g.UserDNI != "11111111" || g.UserName != "Ana" || g.TenantRUC != "20123456789" {
		t.Fatalf("identity missing: %+v", g)
	}
	if _, err := w.pool.Exec(ctx, `UPDATE systems SET session_mode = 'temporary' WHERE id = $1`, w.olympus); err != nil {
		t.Fatal(err)
	}
	if g, _ := repo.Resolve(ctx, w.user, "olympus", ""); g.SessionMode != "temporary" {
		t.Fatalf("temporary policy: %+v", g)
	}
}

func TestListBySystem(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	repo := NewPostgresRepository(w.pool)
	for _, a := range []Access{
		{UserID: w.other, SystemID: w.pulso, TenantID: w.globex, Role: "cajero"},
		{UserID: w.user, SystemID: w.pulso, TenantID: w.acme, Role: "admin", ManageUsers: true},
		{UserID: w.user, SystemID: w.olympus, TenantID: w.acme, Role: "dueño"},
	} {
		if _, err := repo.Assign(ctx, a); err != nil {
			t.Fatal(err)
		}
	}

	list, err := repo.ListBySystem(ctx, w.pulso)
	if err != nil || len(list) != 2 {
		t.Fatalf("got %+v err %v", list, err)
	}
	// Ordered by user name; only the accesses of that system.
	if list[0].UserName != "Ana" || list[0].UserDNI != "11111111" || list[0].Role != "admin" || list[0].TenantName != "Acme" || !list[0].ManageUsers {
		t.Fatalf("got %+v", list[0])
	}
	if list[1].UserName != "Beto" || list[1].Role != "cajero" || list[1].TenantName != "Globex" || list[1].SystemName != "Pulso" {
		t.Fatalf("got %+v", list[1])
	}
	if list, err := repo.ListBySystem(ctx, "00000000-0000-0000-0000-000000000000"); err != nil || len(list) != 0 {
		t.Fatalf("got %+v err %v", list, err)
	}
}
