package role

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const (
	systemID = "11111111-1111-1111-1111-111111111111"
	roleID   = "22222222-2222-2222-2222-222222222222"
)

type fakeRepo struct {
	created Role
	err     error
}

func (f *fakeRepo) Create(_ context.Context, r Role) (Role, error) {
	f.created = r
	return r, f.err
}
func (f *fakeRepo) List(context.Context, string) ([]Role, error) { return nil, f.err }
func (f *fakeRepo) UpdateDescription(_ context.Context, _, _, description string) (Role, error) {
	return Role{Description: description}, f.err
}
func (f *fakeRepo) Delete(context.Context, string, string) error { return f.err }

func TestCreate(t *testing.T) {
	ctx := context.Background()
	long := strings.Repeat("a", 65)
	tests := []struct {
		name string
		in   CreateInput
		want error
	}{
		{"ok", CreateInput{SystemID: systemID, Name: "cajero", Description: "Cobra"}, nil},
		{"trims the name", CreateInput{SystemID: systemID, Name: "  Jefe de Tienda "}, nil},
		{"no description", CreateInput{SystemID: systemID, Name: "admin"}, nil},
		{"empty name", CreateInput{SystemID: systemID, Name: "   "}, ErrInvalidName},
		{"name too long", CreateInput{SystemID: systemID, Name: long}, ErrInvalidName},
		{"control characters", CreateInput{SystemID: systemID, Name: "a\nb"}, ErrInvalidName},
		{"description too long", CreateInput{SystemID: systemID, Name: "x", Description: strings.Repeat("d", 201)}, ErrInvalidDescription},
		{"bad system id", CreateInput{SystemID: "nope", Name: "x"}, ErrInvalidID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeRepo{}
			_, err := NewService(repo).Create(ctx, tt.in)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
			if tt.want != nil && repo.created.Name != "" {
				t.Fatal("an invalid role must not reach the repository")
			}
		})
	}

	t.Run("the name is stored trimmed", func(t *testing.T) {
		repo := &fakeRepo{}
		_, _ = NewService(repo).Create(ctx, CreateInput{SystemID: systemID, Name: "  Jefe de Tienda ", Description: "  Dirige  "})
		if repo.created.Name != "Jefe de Tienda" || repo.created.Description != "Dirige" {
			t.Fatalf("got %+v", repo.created)
		}
	})
	t.Run("repository errors pass through", func(t *testing.T) {
		for _, want := range []error{ErrRoleExists, ErrSystemNotFound} {
			if _, err := NewService(&fakeRepo{err: want}).Create(ctx, CreateInput{SystemID: systemID, Name: "x"}); !errors.Is(err, want) {
				t.Fatalf("got %v, want %v", err, want)
			}
		}
	})
}

func TestUpdateAndDelete(t *testing.T) {
	ctx := context.Background()
	svc := NewService(&fakeRepo{})
	if _, err := svc.UpdateDescription(ctx, "x", roleID, "d"); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("got %v", err)
	}
	if _, err := svc.UpdateDescription(ctx, systemID, roleID, strings.Repeat("d", 201)); !errors.Is(err, ErrInvalidDescription) {
		t.Fatalf("got %v", err)
	}
	if r, err := svc.UpdateDescription(ctx, systemID, roleID, "  nueva "); err != nil || r.Description != "nueva" {
		t.Fatalf("got %+v err %v", r, err)
	}
	if err := svc.Delete(ctx, systemID, "nope"); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("got %v", err)
	}
	if err := NewService(&fakeRepo{err: ErrRoleInUse}).Delete(ctx, systemID, roleID); !errors.Is(err, ErrRoleInUse) {
		t.Fatalf("got %v", err)
	}
	if _, err := svc.List(ctx, "nope"); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("got %v", err)
	}
}
