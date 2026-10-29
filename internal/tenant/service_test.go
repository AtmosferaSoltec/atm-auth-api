package tenant

import (
	"context"
	"errors"
	"testing"
)

type fakeRepo struct {
	byRUC   map[string]Tenant
	enabled map[string]bool
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{byRUC: map[string]Tenant{}, enabled: map[string]bool{}}
}

func (f *fakeRepo) Create(_ context.Context, t Tenant) (Tenant, error) {
	if _, ok := f.byRUC[t.RUC]; ok {
		return Tenant{}, ErrRUCTaken
	}
	t.ID = "id-" + t.RUC
	f.byRUC[t.RUC] = t
	return t, nil
}

func (f *fakeRepo) GetByID(_ context.Context, id string) (Tenant, error) {
	for _, t := range f.byRUC {
		if t.ID == id {
			return t, nil
		}
	}
	return Tenant{}, ErrTenantNotFound
}

func (f *fakeRepo) List(context.Context) ([]Tenant, error) { return nil, nil }

func (f *fakeRepo) EnableSystem(_ context.Context, tenantID, systemID string) error {
	key := tenantID + "|" + systemID
	if f.enabled[key] {
		return ErrSystemAlreadyEnabled
	}
	f.enabled[key] = true
	return nil
}

func TestCreate(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		in   CreateInput
		want error
	}{
		{"ok", CreateInput{RUC: "20123456789", LegalName: "Acme SAC", TradeName: "Acme"}, nil},
		{"ok without trade name", CreateInput{RUC: "20123456789", LegalName: "Acme SAC"}, nil},
		{"short ruc", CreateInput{RUC: "2012345678", LegalName: "Acme"}, ErrInvalidRUC},
		{"ruc with letters", CreateInput{RUC: "2012345678a", LegalName: "Acme"}, ErrInvalidRUC},
		{"empty legal name", CreateInput{RUC: "20123456789", LegalName: "  "}, ErrInvalidLegalName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewService(newFakeRepo()).Create(ctx, tt.in)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}

	t.Run("duplicate ruc", func(t *testing.T) {
		svc := NewService(newFakeRepo())
		in := CreateInput{RUC: "20123456789", LegalName: "Acme"}
		_, _ = svc.Create(ctx, in)
		if _, err := svc.Create(ctx, in); !errors.Is(err, ErrRUCTaken) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestDisplayName(t *testing.T) {
	if got := (Tenant{LegalName: "Acme SAC", TradeName: "Acme"}).DisplayName(); got != "Acme" {
		t.Fatalf("got %q", got)
	}
	if got := (Tenant{LegalName: "Acme SAC"}).DisplayName(); got != "Acme SAC" {
		t.Fatalf("got %q", got)
	}
}

func TestIDValidation(t *testing.T) {
	svc := NewService(newFakeRepo())
	ctx := context.Background()
	if _, err := svc.Get(ctx, "not-a-uuid"); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("got %v", err)
	}
	if err := svc.EnableSystem(ctx, "x", "y"); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("got %v", err)
	}
}
