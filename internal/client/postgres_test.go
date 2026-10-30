package client

import (
	"context"
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
	"github.com/AtmosferaSoltec/atm-auth-api/migrations"
)

const missingID = "00000000-0000-0000-0000-000000000000"

func TestPostgresRepository(t *testing.T) {
	ctx := context.Background()
	pool := platform.NewTestPool(t)
	repo := NewPostgresRepository(pool)

	percy, err := repo.Create(ctx, "Percy")
	if err != nil || percy.ID == "" {
		t.Fatalf("got %+v err %v", percy, err)
	}
	if _, err := repo.GetByID(ctx, missingID); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("got %v", err)
	}
	if err := repo.Update(ctx, percy.ID, "Percy Tasayco"); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, missingID, "x"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("got %v", err)
	}

	for _, ruc := range []string{"20111111111", "20222222222"} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (ruc, legal_name, client_id) VALUES ($1, $2, $3)`, ruc, "Empresa "+ruc, percy.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := repo.Create(ctx, "Tabernero"); err != nil {
		t.Fatal(err)
	}

	got, err := repo.GetByID(ctx, percy.ID)
	if err != nil || got.Name != "Percy Tasayco" || len(got.Tenants) != 2 {
		t.Fatalf("got %+v err %v", got, err)
	}
	list, err := repo.List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("got %+v err %v", list, err)
	}
	if list[0].Name != "Percy Tasayco" || len(list[0].Tenants) != 2 || list[1].Name != "Tabernero" || len(list[1].Tenants) != 0 {
		t.Fatalf("companies must stay with their own client: %+v", list)
	}

	// A client that still owns companies cannot be deleted; an empty one can.
	if err := repo.Delete(ctx, percy.ID); !errors.Is(err, ErrClientHasTenants) {
		t.Fatalf("got %v", err)
	}
	if err := repo.Delete(ctx, list[1].ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.Delete(ctx, list[1].ID); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("got %v", err)
	}
}

// Companies that existed before clients get one each, named after them, and none is left without a client.
func TestMigrationGivesEveryExistingCompanyItsOwnClient(t *testing.T) {
	ctx := context.Background()
	pool := platform.NewTestPool(t)

	if _, err := pool.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public"); err != nil {
		t.Fatal(err)
	}
	before := fstest.MapFS{}
	all, err := fs.Glob(migrations.Files, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range all {
		if name == "0011_clients.sql" {
			continue
		}
		data, err := fs.ReadFile(migrations.Files, name)
		if err != nil {
			t.Fatal(err)
		}
		before[name] = &fstest.MapFile{Data: data}
	}
	if err := platform.Migrate(ctx, pool, before); err != nil {
		t.Fatal(err)
	}

	for _, row := range [][3]string{
		{"20111111111", "LA VENDIMIA SAC", "La Vendimia"},
		{"20222222222", "SOLO RAZON SOCIAL SAC", ""},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (ruc, legal_name, trade_name) VALUES ($1, $2, $3)`, row[0], row[1], row[2]); err != nil {
			t.Fatal(err)
		}
	}

	if err := platform.Migrate(ctx, pool, migrations.Files); err != nil {
		t.Fatal(err)
	}

	rows, err := pool.Query(ctx, `SELECT t.ruc, c.name FROM tenants t JOIN clients c ON c.id = t.client_id ORDER BY t.ruc`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	want := map[string]string{"20111111111": "La Vendimia", "20222222222": "SOLO RAZON SOCIAL SAC"}
	n := 0
	for rows.Next() {
		var ruc, name string
		if err := rows.Scan(&ruc, &name); err != nil {
			t.Fatal(err)
		}
		if want[ruc] != name {
			t.Fatalf("company %s got client %q, want %q", ruc, name, want[ruc])
		}
		n++
	}
	if n != 2 {
		t.Fatalf("got %d companies with a client, want 2", n)
	}
	var clients int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM clients`).Scan(&clients); err != nil || clients != 2 {
		t.Fatalf("got %d clients err %v", clients, err)
	}
}
