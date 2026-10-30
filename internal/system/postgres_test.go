package system

import (
	"context"
	"errors"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

func TestPostgresRepository(t *testing.T) {
	ctx := context.Background()
	repo := NewPostgresRepository(platform.NewTestPool(t))

	created, err := repo.Create(ctx, System{Code: "olympus", Name: "Olympus", Status: StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" {
		t.Fatal("missing id")
	}
	if _, err := repo.Create(ctx, System{Code: "olympus", Name: "Dup", Status: StatusActive}); !errors.Is(err, ErrCodeTaken) {
		t.Fatalf("got %v", err)
	}
	_, _ = repo.Create(ctx, System{Code: "nova", Name: "Nova", Status: StatusActive})

	list, err := repo.List(ctx)
	if err != nil || len(list) != 2 || list[0].Code != "nova" {
		t.Fatalf("got %+v err %v", list, err)
	}

	got, err := repo.GetByCode(ctx, "olympus")
	if err != nil || got.ID != created.ID {
		t.Fatalf("got %+v err %v", got, err)
	}
	if _, err := repo.GetByCode(ctx, "missing"); !errors.Is(err, ErrSystemNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestPostgresDeleteCascades(t *testing.T) {
	ctx := context.Background()
	pool := platform.NewTestPool(t)
	repo := NewPostgresRepository(pool)

	sys, err := repo.Create(ctx, System{Code: "olympus", Name: "Olympus", Status: StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	var tenantID string
	if err := pool.QueryRow(ctx, `WITH c AS (INSERT INTO clients (name) VALUES ('Gym SAC') RETURNING id) INSERT INTO tenants (ruc, legal_name, client_id) SELECT '20123456789', 'Gym SAC', id FROM c RETURNING id`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenant_systems (tenant_id, system_id) VALUES ($1, $2)`, tenantID, sys.ID); err != nil {
		t.Fatal(err)
	}

	got, err := repo.GetByID(ctx, sys.ID)
	if err != nil || got.Code != "olympus" {
		t.Fatalf("got %+v err %v", got, err)
	}
	if err := repo.Delete(ctx, sys.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetByID(ctx, sys.ID); !errors.Is(err, ErrSystemNotFound) {
		t.Fatalf("got %v", err)
	}
	if err := repo.Delete(ctx, sys.ID); !errors.Is(err, ErrSystemNotFound) {
		t.Fatalf("second delete: got %v", err)
	}

	var left int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenant_systems WHERE system_id = $1`, sys.ID).Scan(&left); err != nil || left != 0 {
		t.Fatalf("tenant_systems left: %d err %v", left, err)
	}
}

func TestPostgresSessionPolicy(t *testing.T) {
	ctx := context.Background()
	pool := platform.NewTestPool(t)
	repo := NewPostgresRepository(pool)

	created, err := repo.Create(ctx, System{Code: "pulso", Name: "Pulso", Status: StatusActive, SessionMode: SessionTemporary})
	if err != nil || created.SessionMode != SessionTemporary {
		t.Fatalf("got %+v err %v", created, err)
	}
	updated, err := repo.UpdateSession(ctx, created.ID, SessionPersistent)
	if err != nil || updated.SessionMode != SessionPersistent {
		t.Fatalf("got %+v err %v", updated, err)
	}
	if got, _ := repo.GetByID(ctx, created.ID); got.SessionMode != SessionPersistent {
		t.Fatalf("not persisted: %+v", got)
	}
	if _, err := repo.UpdateSession(ctx, "00000000-0000-0000-0000-000000000000", SessionPersistent); !errors.Is(err, ErrSystemNotFound) {
		t.Fatalf("got %v", err)
	}
	// The database refuses an unknown mode even if the service is bypassed.
	if _, err := pool.Exec(ctx, `UPDATE systems SET session_mode = 'forever'`); err == nil {
		t.Fatal("database accepted an unknown session mode")
	}
}

func TestPostgresReportsSecret(t *testing.T) {
	ctx := context.Background()
	pool := platform.NewTestPool(t)
	repo := NewPostgresRepository(pool)

	created, err := repo.Create(ctx, System{Code: "olympus", Name: "Olympus", Status: StatusActive})
	if err != nil || created.HasSecret || created.SecretCreatedAt != nil {
		t.Fatalf("got %+v err %v", created, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE systems SET secret_hash = 'h', secret_created_at = now() WHERE id = $1`, created.ID); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetByID(ctx, created.ID)
	if err != nil || !got.HasSecret || got.SecretCreatedAt == nil || got.SecretLastUsedAt != nil {
		t.Fatalf("got %+v err %v", got, err)
	}
}
