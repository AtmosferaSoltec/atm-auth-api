package credential

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const systemID = "11111111-1111-1111-1111-111111111111"

type fakeRepo struct {
	hash    string
	code    string
	active  bool
	touched int
	exists  bool
}

func newFakeRepo() *fakeRepo { return &fakeRepo{code: "olympus", active: true, exists: true} }

func (f *fakeRepo) SetSecret(_ context.Context, id, hash string, _ time.Time) (string, error) {
	if !f.exists || id != systemID {
		return "", ErrSystemNotFound
	}
	f.hash = hash
	return f.code, nil
}

func (f *fakeRepo) ClearSecret(_ context.Context, id string) error {
	if !f.exists || id != systemID {
		return ErrSystemNotFound
	}
	f.hash = ""
	return nil
}

func (f *fakeRepo) FindByCode(_ context.Context, code string) (Credential, error) {
	if !f.exists || code != f.code {
		return Credential{}, ErrInvalidClient
	}
	return Credential{SystemID: systemID, Code: f.code, SecretHash: f.hash, Active: f.active}, nil
}

func (f *fakeRepo) TouchSecret(context.Context, string, time.Time) error { f.touched++; return nil }

func newService(repo *fakeRepo) *Service {
	return NewService(repo, func() time.Time { return time.Unix(1_700_000_000, 0) })
}

func TestGenerate(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newService(repo)

	issued, err := svc.Generate(ctx, systemID)
	if err != nil {
		t.Fatal(err)
	}
	if issued.ClientID != "olympus" || !strings.HasPrefix(issued.ClientSecret, "atm_") || len(issued.ClientSecret) != 4+64 {
		t.Fatalf("unexpected secret: %+v", issued)
	}
	if repo.hash == "" || strings.Contains(repo.hash, issued.ClientSecret) || repo.hash == issued.ClientSecret {
		t.Fatalf("only a hash may be stored, got %q", repo.hash)
	}

	again, _ := svc.Generate(ctx, systemID)
	if again.ClientSecret == issued.ClientSecret {
		t.Fatal("every secret must be different")
	}

	if _, err := svc.Generate(ctx, "not-a-uuid"); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("got %v", err)
	}
	if _, err := svc.Generate(ctx, "22222222-2222-2222-2222-222222222222"); !errors.Is(err, ErrSystemNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestVerify(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	svc := newService(repo)

	if _, err := svc.Verify(ctx, "olympus", "anything"); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("a system without a secret must not verify: %v", err)
	}

	first, _ := svc.Generate(ctx, systemID)
	c, err := svc.Verify(ctx, "olympus", first.ClientSecret)
	if err != nil || c.SystemID != systemID || repo.touched != 1 {
		t.Fatalf("got %+v err %v touched %d", c, err, repo.touched)
	}

	for name, tc := range map[string]struct{ id, secret string }{
		"wrong secret":   {"olympus", "atm_" + strings.Repeat("0", 64)},
		"empty secret":   {"olympus", ""},
		"unknown system": {"nova", first.ClientSecret},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := svc.Verify(ctx, tc.id, tc.secret); !errors.Is(err, ErrInvalidClient) {
				t.Fatalf("got %v", err)
			}
		})
	}

	t.Run("regenerating invalidates the old secret", func(t *testing.T) {
		second, _ := svc.Generate(ctx, systemID)
		if _, err := svc.Verify(ctx, "olympus", first.ClientSecret); !errors.Is(err, ErrInvalidClient) {
			t.Fatalf("old secret still works: %v", err)
		}
		if _, err := svc.Verify(ctx, "olympus", second.ClientSecret); err != nil {
			t.Fatalf("new secret rejected: %v", err)
		}
	})

	t.Run("revoking", func(t *testing.T) {
		current, _ := svc.Generate(ctx, systemID)
		if err := svc.Revoke(ctx, systemID); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Verify(ctx, "olympus", current.ClientSecret); !errors.Is(err, ErrInvalidClient) {
			t.Fatalf("revoked secret still works: %v", err)
		}
		if err := svc.Revoke(ctx, "x"); !errors.Is(err, ErrInvalidID) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("a disabled system does not verify", func(t *testing.T) {
		current, _ := svc.Generate(ctx, systemID)
		repo.active = false
		defer func() { repo.active = true }()
		if _, err := svc.Verify(ctx, "olympus", current.ClientSecret); !errors.Is(err, ErrInvalidClient) {
			t.Fatalf("got %v", err)
		}
	})
}
