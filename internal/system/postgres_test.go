package system

import (
	"context"
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
	"github.com/AtmosferaSoltec/atm-auth-api/migrations"
)

func TestPostgresRepository(t *testing.T) {
	ctx := context.Background()
	pool := platform.NewTestPool(t)
	repo := NewPostgresRepository(pool)

	olympusID := platform.SeedSystem(t, pool, "olympus", "Olympus")
	platform.SeedSystem(t, pool, "nova", "Nova")

	list, err := repo.List(ctx)
	if err != nil || len(list) != 2 || list[0].Code != "nova" {
		t.Fatalf("got %+v err %v", list, err)
	}
	if list[0].Status != StatusActive || list[0].SessionMode != SessionPersistent {
		t.Fatalf("a registered system starts active and persistent: %+v", list[0])
	}

	got, err := repo.GetByCode(ctx, "olympus")
	if err != nil || got.ID != olympusID {
		t.Fatalf("got %+v err %v", got, err)
	}
	if byID, err := repo.GetByID(ctx, olympusID); err != nil || byID.Code != "olympus" {
		t.Fatalf("got %+v err %v", byID, err)
	}
	if _, err := repo.GetByCode(ctx, "missing"); !errors.Is(err, ErrSystemNotFound) {
		t.Fatalf("got %v", err)
	}
	if _, err := repo.GetByID(ctx, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, ErrSystemNotFound) {
		t.Fatalf("got %v", err)
	}
}

// The migrations register the systems of the platform, and running them again changes nothing about a system that
// already exists: its secret, session policy and name stay as the console left them.
func TestMigrationRegistersTheSystemsWithoutTouchingExistingOnes(t *testing.T) {
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
		if name == "0012_seed_systems.sql" {
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

	// A system that already lives in production, customized from the console.
	if _, err := pool.Exec(ctx, `INSERT INTO systems (code, name, session_mode, secret_hash) VALUES ('lavendimia', 'Nombre propio', 'temporary', 'hash')`); err != nil {
		t.Fatal(err)
	}
	if err := platform.Migrate(ctx, pool, migrations.Files); err != nil {
		t.Fatal(err)
	}

	rows, err := pool.Query(ctx, `SELECT code, name, session_mode, secret_hash IS NOT NULL FROM systems ORDER BY code`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type row struct {
		code, name, mode string
		secret           bool
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.code, &r.name, &r.mode, &r.secret); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	want := []row{{"lavendimia", "Nombre propio", "temporary", true}, {"pulso", "Pulso", "persistent", false}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestPostgresSessionPolicy(t *testing.T) {
	ctx := context.Background()
	pool := platform.NewTestPool(t)
	repo := NewPostgresRepository(pool)

	id := platform.SeedSystem(t, pool, "pulso", "Pulso")
	updated, err := repo.UpdateSession(ctx, id, SessionTemporary)
	if err != nil || updated.SessionMode != SessionTemporary {
		t.Fatalf("got %+v err %v", updated, err)
	}
	if updated, err = repo.UpdateSession(ctx, id, SessionPersistent); err != nil || updated.SessionMode != SessionPersistent {
		t.Fatalf("got %+v err %v", updated, err)
	}
	if got, _ := repo.GetByID(ctx, id); got.SessionMode != SessionPersistent {
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

	id := platform.SeedSystem(t, pool, "olympus", "Olympus")
	if created, err := repo.GetByID(ctx, id); err != nil || created.HasSecret || created.SecretCreatedAt != nil {
		t.Fatalf("got %+v err %v", created, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE systems SET secret_hash = 'h', secret_created_at = now() WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetByID(ctx, id)
	if err != nil || !got.HasSecret || got.SecretCreatedAt == nil || got.SecretLastUsedAt != nil {
		t.Fatalf("got %+v err %v", got, err)
	}
}
