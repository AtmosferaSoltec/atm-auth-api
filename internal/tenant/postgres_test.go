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
}

func TestRUCConstraint(t *testing.T) {
	pool := platform.NewTestPool(t)
	_, err := pool.Exec(context.Background(), `INSERT INTO tenants (ruc, legal_name) VALUES ('123', 'x')`)
	if err == nil {
		t.Fatal("database must reject a malformed RUC")
	}
}
