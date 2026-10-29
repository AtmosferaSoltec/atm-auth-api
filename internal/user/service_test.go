package user

import (
	"context"
	"errors"
	"testing"
)

type fakeRepo struct{ byDNI map[string]User }

func newFakeRepo() *fakeRepo { return &fakeRepo{byDNI: map[string]User{}} }

func (f *fakeRepo) Create(_ context.Context, u User) (User, error) {
	if _, ok := f.byDNI[u.DNI]; ok {
		return User{}, ErrDNITaken
	}
	u.ID = "id-" + u.DNI
	f.byDNI[u.DNI] = u
	return u, nil
}

func (f *fakeRepo) List(context.Context) ([]User, error) {
	var out []User
	for _, u := range f.byDNI {
		out = append(out, u)
	}
	return out, nil
}

func (f *fakeRepo) SetPassword(_ context.Context, id, hash string, must bool) error {
	for dni, u := range f.byDNI {
		if u.ID == id {
			u.PasswordHash, u.MustChangePassword = hash, must
			f.byDNI[dni] = u
			return nil
		}
	}
	return ErrUserNotFound
}

func (f *fakeRepo) SetStatus(_ context.Context, id, status string) error {
	for dni, u := range f.byDNI {
		if u.ID == id {
			u.Status = status
			f.byDNI[dni] = u
			return nil
		}
	}
	return ErrUserNotFound
}

func (f *fakeRepo) GetByDNI(_ context.Context, dni string) (User, error) {
	u, ok := f.byDNI[dni]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return u, nil
}

func (f *fakeRepo) GetByID(_ context.Context, id string) (User, error) {
	for _, u := range f.byDNI {
		if u.ID == id {
			return u, nil
		}
	}
	return User{}, ErrUserNotFound
}

type fakeRevoker struct{ revoked []string }

func (f *fakeRevoker) RevokeUserSessions(_ context.Context, id string) error {
	f.revoked = append(f.revoked, id)
	return nil
}

type fakeHasher struct{}

func (fakeHasher) Hash(p string) (string, error) { return "hashed:" + p, nil }

func TestCreate(t *testing.T) {
	ctx := context.Background()
	valid := CreateInput{DNI: "74455518", FullName: "  Joel   Maldonado ", Password: "longenough"}

	tests := []struct {
		name string
		in   CreateInput
		want error
	}{
		{"ok", valid, nil},
		{"short dni", CreateInput{DNI: "123", FullName: "A", Password: "longenough"}, ErrInvalidDNI},
		{"letters in dni", CreateInput{DNI: "7445551a", FullName: "A", Password: "longenough"}, ErrInvalidDNI},
		{"empty name", CreateInput{DNI: "74455518", FullName: "   ", Password: "longenough"}, ErrInvalidName},
		{"weak password", CreateInput{DNI: "74455518", FullName: "A", Password: "short"}, ErrWeakPassword},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewService(newFakeRepo(), fakeHasher{}, &fakeRevoker{}).Create(ctx, tt.in)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}

	t.Run("stores hash and normalized name, never the password", func(t *testing.T) {
		repo := newFakeRepo()
		u, err := NewService(repo, fakeHasher{}, &fakeRevoker{}).Create(ctx, valid)
		if err != nil {
			t.Fatal(err)
		}
		if u.FullName != "Joel Maldonado" || u.PasswordHash != "hashed:longenough" || u.Status != StatusActive {
			t.Fatalf("unexpected user: %+v", u)
		}
	})

	t.Run("duplicate dni", func(t *testing.T) {
		svc := NewService(newFakeRepo(), fakeHasher{}, &fakeRevoker{})
		if _, err := svc.Create(ctx, valid); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Create(ctx, valid); !errors.Is(err, ErrDNITaken) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestCreateWithoutPasswordUsesDNIAndForcesChange(t *testing.T) {
	u, err := NewService(newFakeRepo(), fakeHasher{}, &fakeRevoker{}).Create(context.Background(),
		CreateInput{DNI: "74455518", FullName: "Joel"})
	if err != nil {
		t.Fatal(err)
	}
	if u.PasswordHash != "hashed:74455518" || !u.MustChangePassword {
		t.Fatalf("unexpected user: %+v", u)
	}
}

func TestCreateWithPasswordDoesNotForceChange(t *testing.T) {
	u, _ := NewService(newFakeRepo(), fakeHasher{}, &fakeRevoker{}).Create(context.Background(),
		CreateInput{DNI: "74455518", FullName: "Joel", Password: "chosen-password"})
	if u.MustChangePassword {
		t.Fatal("an explicit password must not force a change")
	}
}

func TestResetPassword(t *testing.T) {
	ctx := context.Background()
	repo, revoker := newFakeRepo(), &fakeRevoker{}
	svc := NewService(repo, fakeHasher{}, revoker)
	u, _ := svc.Create(ctx, CreateInput{DNI: "74455518", FullName: "Joel", Password: "chosen-password"})

	if err := svc.ResetPassword(ctx, u.ID); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("a non-uuid id must be rejected, got %v", err)
	}
	const id = "11111111-1111-1111-1111-111111111111"
	repo.byDNI["74455518"] = User{ID: id, DNI: "74455518", PasswordHash: "x", Status: StatusActive}
	if err := svc.ResetPassword(ctx, id); err != nil {
		t.Fatal(err)
	}
	got := repo.byDNI["74455518"]
	if got.PasswordHash != "hashed:74455518" || !got.MustChangePassword {
		t.Fatalf("unexpected user: %+v", got)
	}
	if len(revoker.revoked) != 1 || revoker.revoked[0] != id {
		t.Fatalf("sessions not revoked: %v", revoker.revoked)
	}
	if err := svc.ResetPassword(ctx, "22222222-2222-2222-2222-222222222222"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestSetStatus(t *testing.T) {
	ctx := context.Background()
	const id = "11111111-1111-1111-1111-111111111111"
	repo, revoker := newFakeRepo(), &fakeRevoker{}
	repo.byDNI["74455518"] = User{ID: id, DNI: "74455518", Status: StatusActive}
	svc := NewService(repo, fakeHasher{}, revoker)

	if err := svc.SetStatus(ctx, id, "banned"); !errors.Is(err, ErrInvalidStatus) {
		t.Fatalf("got %v", err)
	}
	if err := svc.SetStatus(ctx, id, StatusDisabled); err != nil {
		t.Fatal(err)
	}
	if repo.byDNI["74455518"].Status != StatusDisabled || len(revoker.revoked) != 1 {
		t.Fatalf("disable must revoke sessions: %+v %v", repo.byDNI["74455518"], revoker.revoked)
	}
	if err := svc.SetStatus(ctx, id, StatusActive); err != nil || len(revoker.revoked) != 1 {
		t.Fatalf("enabling must not revoke: %v %v", err, revoker.revoked)
	}
}

func TestValidNewPassword(t *testing.T) {
	for pw, want := range map[string]bool{"short": false, "74455518": false, "12345678": true, "a-good-one": true} {
		if got := ValidNewPassword(pw, "74455518"); got != want {
			t.Errorf("%q: got %v, want %v", pw, got, want)
		}
	}
}
