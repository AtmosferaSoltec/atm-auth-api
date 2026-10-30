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
	platform.SeedRoles(t, pool, systemID, "admin")
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

func TestListForSystem(t *testing.T) {
	ctx := context.Background()
	pool := platform.NewTestPool(t)
	repo := NewPostgresRepository(pool)

	tenants := map[string]string{}
	for _, in := range []Tenant{
		{RUC: "20000000001", LegalName: "Beta SAC", TradeName: "Beta", Status: StatusActive},
		{RUC: "20000000002", LegalName: "Alfa SAC", Status: StatusActive},
		{RUC: "20000000003", LegalName: "Gamma SAC", Status: StatusActive},
		{RUC: "20000000004", LegalName: "Delta SAC", Status: StatusActive},
	} {
		created, err := repo.Create(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		tenants[in.RUC] = created.ID
	}
	var lavendimia, pulso string
	for code, dst := range map[string]*string{"lavendimia": &lavendimia, "pulso": &pulso} {
		if err := pool.QueryRow(ctx, `INSERT INTO systems (code, name) VALUES ($1, $1) RETURNING id`, code).Scan(dst); err != nil {
			t.Fatal(err)
		}
	}
	// Beta, Alfa and Gamma have lavendimia; Gamma is switched off for it; Delta only has pulso.
	for _, ruc := range []string{"20000000001", "20000000002", "20000000003"} {
		if err := repo.EnableSystem(ctx, tenants[ruc], lavendimia); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.EnableSystem(ctx, tenants["20000000004"], pulso); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tenant_systems SET status = 'disabled' WHERE tenant_id = $1`, tenants["20000000003"]); err != nil {
		t.Fatal(err)
	}

	got, err := repo.ListForSystem(ctx, "lavendimia")
	if err != nil || len(got) != 2 || got[0].LegalName != "Alfa SAC" || got[1].LegalName != "Beta SAC" || got[1].TradeName != "Beta" {
		t.Fatalf("only the active tenants with the system, by legal name: got %+v err %v", got, err)
	}

	if _, err := pool.Exec(ctx, `UPDATE tenants SET status = 'disabled' WHERE id = $1`, tenants["20000000002"]); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.ListForSystem(ctx, "lavendimia"); len(got) != 1 {
		t.Fatalf("a disabled tenant must leave the list: %+v", got)
	}

	if _, err := pool.Exec(ctx, `UPDATE systems SET status = 'disabled' WHERE id = $1`, lavendimia); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.ListForSystem(ctx, "lavendimia"); len(got) != 0 {
		t.Fatalf("a disabled system serves nobody: %+v", got)
	}
	if got, err := repo.ListForSystem(ctx, "no-existe"); err != nil || len(got) != 0 {
		t.Fatalf("unknown system: got %+v err %v", got, err)
	}
}

func TestPostgresUpdateProfile(t *testing.T) {
	ctx := context.Background()
	repo := NewPostgresRepository(platform.NewTestPool(t))
	created, err := repo.Create(ctx, Tenant{RUC: "20123456789", LegalName: "Acme SAC", Status: StatusActive})
	if err != nil || created.Address != "" || created.LogoFileID != "" {
		t.Fatalf("a new tenant has an empty profile, got %+v err %v", created, err)
	}
	created.TradeName, created.Address, created.Department, created.Province, created.District = "Acme", "Av. Lima 123", "Lima", "Lima", "Miraflores"
	created.Ubigeo, created.Phone, created.Email, created.LogoFileID = "150122", "987654321", "a@acme.pe", "9f1c2a44-7a43-4b0b-8f27-5f0f3f1f2a10"
	if err = repo.Update(ctx, created); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetByID(ctx, created.ID)
	if err != nil || got.District != "Miraflores" || got.Ubigeo != "150122" || got.LogoFileID != created.LogoFileID || got.RUC != "20123456789" {
		t.Fatalf("got %+v err %v", got, err)
	}
	got.LogoFileID = ""
	if err = repo.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if cleared, _ := repo.GetByID(ctx, created.ID); cleared.LogoFileID != "" {
		t.Fatalf("logo not cleared: %+v", cleared)
	}
	got.ID = missingID
	if err = repo.Update(ctx, got); !errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("got %v", err)
	}
	got.ID, got.Ubigeo = created.ID, "12"
	if err = repo.Update(ctx, got); err == nil {
		t.Fatal("the database must reject a malformed ubigeo")
	}
}
