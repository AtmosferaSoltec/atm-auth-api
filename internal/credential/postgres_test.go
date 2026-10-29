package credential

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

func TestPostgresRepository(t *testing.T) {
	ctx := context.Background()
	pool := platform.NewTestPool(t)
	repo := NewPostgresRepository(pool)

	var id string
	if err := pool.QueryRow(ctx, `INSERT INTO systems (code, name) VALUES ('olympus', 'Olympus') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}

	// A system starts without a secret.
	c, err := repo.FindByCode(ctx, "olympus")
	if err != nil || c.SecretHash != "" || !c.Active || c.SystemID != id {
		t.Fatalf("got %+v err %v", c, err)
	}
	if _, err := repo.FindByCode(ctx, "missing"); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("got %v", err)
	}

	at := time.Now()
	code, err := repo.SetSecret(ctx, id, "hash-1", at)
	if err != nil || code != "olympus" {
		t.Fatalf("got %q err %v", code, err)
	}
	if c, _ := repo.FindByCode(ctx, "olympus"); c.SecretHash != "hash-1" {
		t.Fatalf("got %+v", c)
	}

	if err := repo.TouchSecret(ctx, id, at); err != nil {
		t.Fatal(err)
	}
	var used *time.Time
	if err := pool.QueryRow(ctx, `SELECT secret_last_used_at FROM systems WHERE id = $1`, id).Scan(&used); err != nil || used == nil {
		t.Fatalf("last use not stored: %v %v", used, err)
	}

	// Regenerating resets the last use; clearing removes everything.
	if _, err := repo.SetSecret(ctx, id, "hash-2", at); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT secret_last_used_at FROM systems WHERE id = $1`, id).Scan(&used); err != nil || used != nil {
		t.Fatalf("last use must reset: %v %v", used, err)
	}
	if err := repo.ClearSecret(ctx, id); err != nil {
		t.Fatal(err)
	}
	if c, _ := repo.FindByCode(ctx, "olympus"); c.SecretHash != "" {
		t.Fatalf("secret not cleared: %+v", c)
	}

	missing := "00000000-0000-0000-0000-000000000000"
	if _, err := repo.SetSecret(ctx, missing, "h", at); !errors.Is(err, ErrSystemNotFound) {
		t.Fatalf("got %v", err)
	}
	if err := repo.ClearSecret(ctx, missing); !errors.Is(err, ErrSystemNotFound) {
		t.Fatalf("got %v", err)
	}

	// A disabled system reports itself as inactive.
	if _, err := pool.Exec(ctx, `UPDATE systems SET status = 'disabled' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if c, _ := repo.FindByCode(ctx, "olympus"); c.Active {
		t.Fatalf("got %+v", c)
	}
}
