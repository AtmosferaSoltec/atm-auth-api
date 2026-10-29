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
