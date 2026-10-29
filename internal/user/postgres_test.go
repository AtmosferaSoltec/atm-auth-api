package user

import (
	"context"
	"errors"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

func TestPostgresRepository(t *testing.T) {
	ctx := context.Background()
	repo := NewPostgresRepository(platform.NewTestPool(t))

	created, err := repo.Create(ctx, User{DNI: "74455518", FullName: "Joel", PasswordHash: "h", Status: StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.CreatedAt.IsZero() {
		t.Fatalf("generated fields missing: %+v", created)
	}

	got, err := repo.GetByDNI(ctx, "74455518")
	if err != nil || got.ID != created.ID {
		t.Fatalf("got %+v err %v", got, err)
	}

	if _, err := repo.GetByDNI(ctx, "00000000"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("got %v", err)
	}
	if _, err := repo.Create(ctx, User{DNI: "74455518", FullName: "Dup", PasswordHash: "h", Status: StatusActive}); !errors.Is(err, ErrDNITaken) {
		t.Fatalf("got %v", err)
	}
}

func TestPostgresPasswordStatusAndList(t *testing.T) {
	ctx := context.Background()
	repo := NewPostgresRepository(platform.NewTestPool(t))
	u, err := repo.Create(ctx, User{DNI: "74455518", FullName: "Joel", PasswordHash: "h1", Status: StatusActive, MustChangePassword: true})
	if err != nil || !u.MustChangePassword {
		t.Fatalf("got %+v err %v", u, err)
	}

	if err := repo.SetPassword(ctx, u.ID, "h2", false); err != nil {
		t.Fatal(err)
	}
	got, _ := repo.GetByID(ctx, u.ID)
	if got.PasswordHash != "h2" || got.MustChangePassword {
		t.Fatalf("got %+v", got)
	}
	if err := repo.SetStatus(ctx, u.ID, StatusDisabled); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.GetByID(ctx, u.ID); got.Status != StatusDisabled {
		t.Fatalf("got %+v", got)
	}

	const missing = "00000000-0000-0000-0000-000000000000"
	if err := repo.SetPassword(ctx, missing, "h", false); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("got %v", err)
	}
	if err := repo.SetStatus(ctx, missing, StatusActive); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("got %v", err)
	}
	if list, err := repo.List(ctx); err != nil || len(list) != 1 {
		t.Fatalf("got %+v err %v", list, err)
	}
}
