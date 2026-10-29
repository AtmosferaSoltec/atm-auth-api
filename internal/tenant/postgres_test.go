package tenant

import (
	"context"
	"errors"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

const missingID = "00000000-0000-0000-0000-000000000000"

func TestPostgresRepository(t *testing.T) {
	ctx := context.Background()
	pool := platform.NewTestPool(t)
	repo := NewPostgresRepository(pool)

	created, err := repo.Create(ctx, Tenant{RUC: "20123456789", LegalName: "Acme SAC", TradeName: "Acme", Status: StatusActive})
	if err != nil || created.ID == "" {
		t.Fatalf("got %+v err %v", created, err)
	}
	if _, err := repo.Create(ctx, Tenant{RUC: "20123456789", LegalName: "Dup", Status: StatusActive}); !errors.Is(err, ErrRUCTaken) {
		t.Fatalf("got %v", err)
	}
	if got, err := repo.GetByID(ctx, created.ID); err != nil || got.RUC != "20123456789" {
		t.Fatalf("got %+v err %v", got, err)
	}
	if _, err := repo.GetByID(ctx, missingID); !errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("got %v", err)
	}
	if list, err := repo.List(ctx); err != nil || len(list) != 1 {
		t.Fatalf("got %+v err %v", list, err)
	}

	var systemID string
	if err := pool.QueryRow(ctx, `INSERT INTO systems (code, name) VALUES ('olympus', 'Olympus') RETURNING id`).Scan(&systemID); err != nil {
		t.Fatal(err)
	}
	if err := repo.EnableSystem(ctx, created.ID, systemID); err != nil {
		t.Fatal(err)
	}
	if err := repo.EnableSystem(ctx, created.ID, systemID); !errors.Is(err, ErrSystemAlreadyEnabled) {
		t.Fatalf("got %v", err)
	}
	if err := repo.EnableSystem(ctx, missingID, systemID); !errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("got %v", err)
	}
	if err := repo.EnableSystem(ctx, created.ID, missingID); !errors.Is(err, ErrSystemNotFound) {
		t.Fatalf("got %v", err)
	}

	// The enabled systems come with the tenant, ordered by code.
	var pulsoID string
	if err := pool.QueryRow(ctx, `INSERT INTO systems (code, name) VALUES ('pulso', 'Pulso') RETURNING id`).Scan(&pulsoID); err != nil {
		t.Fatal(err)
	}
	if err := repo.EnableSystem(ctx, created.ID, pulsoID); err != nil {
		t.Fatal(err)
	}
	other, err := repo.Create(ctx, Tenant{RUC: "20987654321", LegalName: "Otra SAC", Status: StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetByID(ctx, created.ID)
	if err != nil || len(got.Systems) != 2 || got.Systems[0].Code != "olympus" || got.Systems[1].Name != "Pulso" {
		t.Fatalf("got %+v err %v", got.Systems, err)
	}
	list, err := repo.List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("got %+v err %v", list, err)
	}
	for _, tn := range list {
		switch tn.ID {
		case created.ID:
			if len(tn.Systems) != 2 {
				t.Fatalf("acme systems: %+v", tn.Systems)
			}
		case other.ID:
			if len(tn.Systems) != 0 {
				t.Fatalf("a tenant must not get another tenant's systems: %+v", tn.Systems)
			}
		}
	}
}

func TestPostgresDisableSystem(t *testing.T) {
	ctx := context.Background()
	pool := platform.NewTestPool(t)
	repo := NewPostgresRepository(pool)

	tn, err := repo.Create(ctx, Tenant{RUC: "20123456789", LegalName: "Acme SAC", Status: StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	var systemID, userID string
	if err := pool.QueryRow(ctx, `INSERT INTO systems (code, name) VALUES ('olympus', 'Olympus') RETURNING id`).Scan(&systemID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO users (dni, full_name, password_hash) VALUES ('11111111', 'Ana', 'x') RETURNING id`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := repo.EnableSystem(ctx, tn.ID, systemID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access (user_id, system_id, tenant_id, role) VALUES ($1, $2, $3, 'admin')`, userID, systemID, tn.ID); err != nil {
		t.Fatal(err)
	}

	if err := repo.DisableSystem(ctx, tn.ID, systemID); err != nil {
		t.Fatal(err)
	}
	if err := repo.DisableSystem(ctx, tn.ID, systemID); !errors.Is(err, ErrSystemNotEnabled) {
		t.Fatalf("second disable: got %v", err)
	}
	var left int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM access WHERE tenant_id = $1 AND system_id = $2`, tn.ID, systemID).Scan(&left); err != nil || left != 0 {
		t.Fatalf("access must go with the enablement: %d err %v", left, err)
	}
	var users int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE id = $1`, userID).Scan(&users); err != nil || users != 1 {
		t.Fatalf("the user account must stay: %d err %v", users, err)
	}
}

func TestRUCConstraint(t *testing.T) {
	pool := platform.NewTestPool(t)
	_, err := pool.Exec(context.Background(), `INSERT INTO tenants (ruc, legal_name) VALUES ('123', 'x')`)
	if err == nil {
		t.Fatal("database must reject a malformed RUC")
	}
}
