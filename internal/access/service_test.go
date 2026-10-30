package access

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const (
	u1 = "11111111-1111-1111-1111-111111111111"
	s1 = "22222222-2222-2222-2222-222222222222"
	t1 = "33333333-3333-3333-3333-333333333333"
)

type fakeRepo struct{ last Access }

func (f *fakeRepo) Assign(_ context.Context, a Access) (Access, error)     { f.last = a; return a, nil }
func (f *fakeRepo) ListByUser(context.Context, string) ([]Detail, error)   { return nil, nil }
func (f *fakeRepo) ListBySystem(context.Context, string) ([]Detail, error) { return nil, nil }
func (f *fakeRepo) Remove(context.Context, string, string) error           { return nil }
func (f *fakeRepo) RemoveByID(context.Context, string) error               { return nil }

func (f *fakeRepo) Options(context.Context, string, string) ([]Option, error) { return nil, nil }

func (f *fakeRepo) MarkUsed(context.Context, string, string, string) error { return nil }

func (f *fakeRepo) Resolve(context.Context, string, string, string) (Grant, error) {
	return Grant{}, ErrNoAccess
}

func TestListBySystemValidatesID(t *testing.T) {
	if _, err := NewService(&fakeRepo{}).ListBySystem(context.Background(), "not-a-uuid"); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("got %v", err)
	}
}

func TestAssignValidation(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		in   AssignInput
		want error
	}{
		{"ok", AssignInput{UserID: u1, SystemID: s1, TenantID: t1, Role: "cajero"}, nil},
		{"role with spaces and accents", AssignInput{UserID: u1, SystemID: s1, TenantID: t1, Role: "  Jefe de Tienda "}, nil},
		{"bad user id", AssignInput{UserID: "x", SystemID: s1, TenantID: t1, Role: "r"}, ErrInvalidID},
		{"bad system id", AssignInput{UserID: u1, SystemID: "x", TenantID: t1, Role: "r"}, ErrInvalidID},
		{"bad tenant id", AssignInput{UserID: u1, SystemID: s1, TenantID: "x", Role: "r"}, ErrInvalidID},
		{"empty role", AssignInput{UserID: u1, SystemID: s1, TenantID: t1, Role: "   "}, ErrInvalidRole},
		{"role too long", AssignInput{UserID: u1, SystemID: s1, TenantID: t1, Role: strings.Repeat("a", 65)}, ErrInvalidRole},
		{"role with control char", AssignInput{UserID: u1, SystemID: s1, TenantID: t1, Role: "a\nb"}, ErrInvalidRole},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewService(&fakeRepo{}).Assign(ctx, tt.in)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}

	t.Run("role is trimmed before storing", func(t *testing.T) {
		repo := &fakeRepo{}
		_, _ = NewService(repo).Assign(ctx, AssignInput{UserID: u1, SystemID: s1, TenantID: t1, Role: "  Jefe de Tienda "})
		if repo.last.Role != "Jefe de Tienda" {
			t.Fatalf("got %q", repo.last.Role)
		}
	})
}

func TestRemoveValidation(t *testing.T) {
	if err := NewService(&fakeRepo{}).Remove(context.Background(), "x", s1); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("got %v", err)
	}
}
