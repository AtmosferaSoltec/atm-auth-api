package tenant

import (
	"context"
	"errors"
	"strings"
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
	t.ID = "00000000-0000-0000-0000-0" + t.RUC // 12 digits after the last dash: a valid UUID
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

func (f *fakeRepo) Update(_ context.Context, t Tenant) error {
	for ruc, current := range f.byRUC {
		if current.ID == t.ID {
			t.RUC, t.Status = current.RUC, current.Status
			f.byRUC[ruc] = t
			return nil
		}
	}
	return ErrTenantNotFound
}

func (f *fakeRepo) List(context.Context) ([]Tenant, error) { return nil, nil }

func (f *fakeRepo) SetClient(context.Context, string, string) error { return nil }

func (f *fakeRepo) ListForSystem(context.Context, string) ([]Tenant, error) { return nil, nil }

func (f *fakeRepo) EnableSystem(_ context.Context, tenantID, systemID string) error {
	key := tenantID + "|" + systemID
	if f.enabled[key] {
		return ErrSystemAlreadyEnabled
	}
	f.enabled[key] = true
	return nil
}

func (f *fakeRepo) DisableSystem(_ context.Context, tenantID, systemID string) error {
	key := tenantID + "|" + systemID
	if !f.enabled[key] {
		return ErrSystemNotEnabled
	}
	delete(f.enabled, key)
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
	if err := svc.DisableSystem(ctx, "x", "y"); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("got %v", err)
	}
}

func TestDisableSystem(t *testing.T) {
	ctx := context.Background()
	const tenantID, systemID = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	svc := NewService(newFakeRepo())

	if err := svc.DisableSystem(ctx, tenantID, systemID); !errors.Is(err, ErrSystemNotEnabled) {
		t.Fatalf("not enabled: got %v", err)
	}
	if err := svc.EnableSystem(ctx, tenantID, systemID); err != nil {
		t.Fatal(err)
	}
	if err := svc.DisableSystem(ctx, tenantID, systemID); err != nil {
		t.Fatalf("got %v", err)
	}
	if err := svc.DisableSystem(ctx, tenantID, systemID); !errors.Is(err, ErrSystemNotEnabled) {
		t.Fatalf("second disable: got %v", err)
	}
}

func TestListForSystemNeedsACode(t *testing.T) {
	svc := NewService(newFakeRepo())
	if _, err := svc.ListForSystem(context.Background(), ""); !errors.Is(err, ErrSystemNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestUpdateProfile(t *testing.T) {
	ctx := context.Background()
	svc := NewService(newFakeRepo())
	created, err := svc.Create(ctx, CreateInput{RUC: "20123456789", LegalName: "Acme SAC"})
	if err != nil {
		t.Fatal(err)
	}
	full := UpdateInput{
		LegalName: "  Acme   SAC ", TradeName: "Acme", Address: "Av. Lima 123", Department: "Lima", Province: "Lima", District: "Miraflores",
		Ubigeo: "150122", Phone: "+51 987 654 321", Email: "ventas@acme.pe", LogoFileID: "9f1c2a44-7a43-4b0b-8f27-5f0f3f1f2a10",
	}
	got, err := svc.Update(ctx, created.ID, full)
	if err != nil || got.LegalName != "Acme SAC" || got.Ubigeo != "150122" || got.District != "Miraflores" || got.RUC != "20123456789" {
		t.Fatalf("got %+v err %v", got, err)
	}
	// Everything but the legal name is optional: an empty profile clears the data.
	got, err = svc.Update(ctx, created.ID, UpdateInput{LegalName: "Acme SAC"})
	if err != nil || got.Address != "" || got.Ubigeo != "" || got.Email != "" || got.LogoFileID != "" {
		t.Fatalf("got %+v err %v", got, err)
	}

	for name, tc := range map[string]struct {
		change func(*UpdateInput)
		want   error
	}{
		"no legal name": {func(in *UpdateInput) { in.LegalName = "  " }, ErrInvalidLegalName},
		"short ubigeo":  {func(in *UpdateInput) { in.Ubigeo = "1501" }, ErrInvalidUbigeo},
		"letter ubigeo": {func(in *UpdateInput) { in.Ubigeo = "15012X" }, ErrInvalidUbigeo},
		"bad email":     {func(in *UpdateInput) { in.Email = "no-es-correo" }, ErrInvalidEmail},
		"named email":   {func(in *UpdateInput) { in.Email = "Acme <a@acme.pe>" }, ErrInvalidEmail},
		"bad phone":     {func(in *UpdateInput) { in.Phone = "call me" }, ErrInvalidPhone},
		"long phone":    {func(in *UpdateInput) { in.Phone = "123456789012345678901" }, ErrInvalidPhone},
		"bad logo":      {func(in *UpdateInput) { in.LogoFileID = "https://x/logo.png" }, ErrInvalidLogo},
		"long address":  {func(in *UpdateInput) { in.Address = strings.Repeat("a", 256) }, ErrFieldTooLong},
	} {
		in := full
		tc.change(&in)
		if _, err := svc.Update(ctx, created.ID, in); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v want %v", name, err, tc.want)
		}
	}
	if _, err := svc.Update(ctx, "not-a-uuid", full); !errors.Is(err, ErrInvalidID) {
		t.Errorf("got %v", err)
	}
	if _, err := svc.Update(ctx, missingID, full); !errors.Is(err, ErrTenantNotFound) {
		t.Errorf("got %v", err)
	}
}
