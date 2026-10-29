package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

func TestPostgresRefreshTokens(t *testing.T) {
	ctx := context.Background()
	repo := NewPostgresRepository(platform.NewTestPool(t))
	exp := time.Now().Add(time.Hour)

	created, err := repo.Create(ctx, RefreshToken{TokenHash: "h1", Role: RoleSuperadmin, ExpiresAt: exp})
	if err != nil || created.ID == "" || created.FamilyID == "" {
		t.Fatalf("got %+v err %v", created, err)
	}

	got, err := repo.FindByHash(ctx, "h1")
	if err != nil || got.ID != created.ID || got.UserID != "" || got.UsedAt != nil {
		t.Fatalf("got %+v err %v", got, err)
	}
	if _, err := repo.FindByHash(ctx, "missing"); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("got %v", err)
	}

	won, err := repo.MarkUsed(ctx, created.ID, time.Now())
	if err != nil || !won {
		t.Fatalf("first MarkUsed: %v %v", won, err)
	}
	if won, _ := repo.MarkUsed(ctx, created.ID, time.Now()); won {
		t.Fatal("second MarkUsed must lose")
	}

	child, err := repo.Create(ctx, RefreshToken{FamilyID: created.FamilyID, TokenHash: "h2", Role: RoleSuperadmin, ExpiresAt: exp})
	if err != nil || child.FamilyID != created.FamilyID {
		t.Fatalf("family not kept: %+v err %v", child, err)
	}
	if err := repo.RevokeFamily(ctx, created.FamilyID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.FindByHash(ctx, "h2"); got.RevokedAt == nil {
		t.Fatal("family member not revoked")
	}
	if won, _ := repo.MarkUsed(ctx, child.ID, time.Now()); won {
		t.Fatal("revoked token must not be usable")
	}
}

func TestPostgresRoleConstraint(t *testing.T) {
	repo := NewPostgresRepository(platform.NewTestPool(t))
	_, err := repo.Create(context.Background(), RefreshToken{TokenHash: "bad", Role: RoleUser, ExpiresAt: time.Now().Add(time.Hour)})
	if err == nil {
		t.Fatal("a user token without user and system must be rejected")
	}
}

func TestPostgresAttempts(t *testing.T) {
	ctx := context.Background()
	repo := NewPostgresRepository(platform.NewTestPool(t))
	now := time.Now().UTC().Truncate(time.Microsecond)
	window := 15 * time.Minute

	if n, _, err := repo.Failures(ctx, "k", now.Add(-window)); err != nil || n != 0 {
		t.Fatalf("got %d err %v", n, err)
	}
	first := now.Add(-5 * time.Minute)
	_ = repo.Record(ctx, "k", first, now.Add(-window))
	_ = repo.Record(ctx, "k", now, now.Add(-window))
	_ = repo.Record(ctx, "other", now, now.Add(-window))

	n, oldest, err := repo.Failures(ctx, "k", now.Add(-window))
	if err != nil || n != 2 || !oldest.Equal(first) {
		t.Fatalf("got %d %v err %v", n, oldest, err)
	}

	// Recording prunes entries older than the cutoff.
	_ = repo.Record(ctx, "k", now, now.Add(-time.Minute))
	if n, _, _ := repo.Failures(ctx, "k", now.Add(-time.Hour)); n != 2 {
		t.Fatalf("old failure not pruned, count %d", n)
	}

	if err := repo.Clear(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if n, _, _ := repo.Failures(ctx, "k", now.Add(-time.Hour)); n != 0 {
		t.Fatalf("not cleared: %d", n)
	}
	if n, _, _ := repo.Failures(ctx, "other", now.Add(-time.Hour)); n != 1 {
		t.Fatal("clear must only affect its own key")
	}
}
