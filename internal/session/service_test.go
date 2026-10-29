package session

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/access"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/user"
)

type fakeRefreshStore struct {
	byHash map[string]*RefreshToken
	next   int
}

func newFakeRefreshStore() *fakeRefreshStore {
	return &fakeRefreshStore{byHash: map[string]*RefreshToken{}}
}

func (f *fakeRefreshStore) Create(_ context.Context, t RefreshToken) (RefreshToken, error) {
	f.next++
	t.ID = "id" + strconv.Itoa(f.next)
	if t.FamilyID == "" {
		t.FamilyID = "fam" + strconv.Itoa(f.next)
	}
	f.byHash[t.TokenHash] = &t
	return t, nil
}

func (f *fakeRefreshStore) FindByHash(_ context.Context, hash string) (RefreshToken, error) {
	t, ok := f.byHash[hash]
	if !ok {
		return RefreshToken{}, ErrInvalidRefreshToken
	}
	return *t, nil
}

func (f *fakeRefreshStore) MarkUsed(_ context.Context, id string, at time.Time) (bool, error) {
	for _, t := range f.byHash {
		if t.ID == id {
			if t.UsedAt != nil || t.RevokedAt != nil {
				return false, nil
			}
			t.UsedAt = &at
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeRefreshStore) RevokeFamily(_ context.Context, fam string, at time.Time) error {
	for _, t := range f.byHash {
		if t.FamilyID == fam && t.RevokedAt == nil {
			t.RevokedAt = &at
		}
	}
	return nil
}

func (f *fakeRefreshStore) RevokeUser(_ context.Context, userID string, at time.Time) error {
	for _, t := range f.byHash {
		if t.UserID == userID && t.RevokedAt == nil {
			t.RevokedAt = &at
		}
	}
	return nil
}

type fakeAttempts struct{ failures map[string][]time.Time }

func newFakeAttempts() *fakeAttempts { return &fakeAttempts{failures: map[string][]time.Time{}} }

func (f *fakeAttempts) Failures(_ context.Context, key string, since time.Time) (int, time.Time, error) {
	var n int
	var oldest time.Time
	for _, at := range f.failures[key] {
		if at.After(since) {
			if n == 0 || at.Before(oldest) {
				oldest = at
			}
			n++
		}
	}
	return n, oldest, nil
}

func (f *fakeAttempts) Record(_ context.Context, key string, at, _ time.Time) error {
	f.failures[key] = append(f.failures[key], at)
	return nil
}

func (f *fakeAttempts) Clear(_ context.Context, key string) error {
	delete(f.failures, key)
	return nil
}

// fakeHasher treats the stored "hash" as the plain password.
type fakeHasher struct{}

func (fakeHasher) Hash(password string) (string, error) { return password, nil }

func (fakeHasher) Verify(password, hash string) (bool, error) { return password == hash, nil }

type fakeSigner struct{ last platform.Claims }

func (f *fakeSigner) Sign(c platform.Claims) (string, error) {
	f.last = c
	return "access-" + c.Subject, nil
}

type fakeUsers struct{ byDNI map[string]user.User }

func (f *fakeUsers) GetByDNI(_ context.Context, dni string) (user.User, error) {
	if u, ok := f.byDNI[dni]; ok {
		return u, nil
	}
	return user.User{}, user.ErrUserNotFound
}

func (f *fakeUsers) SetPassword(_ context.Context, id, hash string, must bool) error {
	for dni, u := range f.byDNI {
		if u.ID == id {
			u.PasswordHash, u.MustChangePassword = hash, must
			f.byDNI[dni] = u
			return nil
		}
	}
	return user.ErrUserNotFound
}

func (f *fakeUsers) GetByID(_ context.Context, id string) (user.User, error) {
	for _, u := range f.byDNI {
		if u.ID == id {
			return u, nil
		}
	}
	return user.User{}, user.ErrUserNotFound
}

// fakeAccess holds grants keyed by "userID|systemCode".
type fakeAccess struct{ grants map[string]access.Grant }

func (f *fakeAccess) Resolve(_ context.Context, userID, systemCode string) (access.Grant, error) {
	if g, ok := f.grants[userID+"|"+systemCode]; ok {
		return g, nil
	}
	return access.Grant{}, access.ErrNoAccess
}

type fixture struct {
	svc      *Service
	refresh  *fakeRefreshStore
	attempts *fakeAttempts
	signer   *fakeSigner
	users    *fakeUsers
	access   *fakeAccess
	now      *time.Time
}

func newFixture() *fixture {
	now := time.Unix(1_700_000_000, 0)
	f := &fixture{
		refresh: newFakeRefreshStore(), attempts: newFakeAttempts(), signer: &fakeSigner{}, now: &now,
		users: &fakeUsers{byDNI: map[string]user.User{
			"11111111": {ID: "u1", DNI: "11111111", PasswordHash: "user-password", Status: user.StatusActive},
			"22222222": {ID: "u2", DNI: "22222222", PasswordHash: "user-password", Status: user.StatusDisabled},
			"33333333": {ID: "u3", DNI: "33333333", PasswordHash: "33333333", Status: user.StatusActive, MustChangePassword: true},
		}},
		access: &fakeAccess{grants: map[string]access.Grant{
			"u1|olympus": {SystemID: "s1", SystemCode: "olympus", TenantID: "t1", Role: "cajero"},
			"u2|olympus": {SystemID: "s1", SystemCode: "olympus", TenantID: "t1", Role: "cajero"},
			"u3|olympus": {SystemID: "s1", SystemCode: "olympus", TenantID: "t1", Role: "cajero"},
		}},
	}
	f.svc = NewService(Deps{
		Tokens: f.refresh, Attempts: f.attempts, Users: f.users, Access: f.access,
		Hasher: fakeHasher{}, Signer: f.signer,
	}, Config{
		Admin:      AdminCredentials{DNI: "74455518", PasswordHash: "right-password"},
		DummyHash:  "dummy",
		Limits:     Limits{MaxPerSubject: 3, MaxPerIP: 5, Window: 15 * time.Minute},
		AccessTTL:  10 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	}, func() time.Time { return *f.now })
	return f
}

func TestAdminLogin(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		f := newFixture()
		tokens, err := f.svc.AdminLogin(ctx, "74455518", "right-password", "1.1.1.1")
		if err != nil {
			t.Fatal(err)
		}
		if tokens.AccessToken != "access-admin" || tokens.RefreshToken == "" || tokens.ExpiresIn != 600 {
			t.Fatalf("unexpected tokens: %+v", tokens)
		}
		c := f.signer.last
		if c.Role != RoleSuperadmin || c.Subject != AdminSubject || c.System != "" || c.ExpiresAt-c.IssuedAt != 600 {
			t.Fatalf("unexpected claims: %+v", c)
		}
		if _, ok := f.refresh.byHash[tokens.RefreshToken]; ok {
			t.Fatal("raw refresh token must not be stored")
		}
		if _, ok := f.refresh.byHash[hashToken(tokens.RefreshToken)]; !ok {
			t.Fatal("hashed refresh token not stored")
		}
	})

	for name, tc := range map[string]struct{ dni, pw string }{
		"wrong password": {"74455518", "nope"},
		"wrong dni":      {"00000000", "right-password"},
		"both wrong":     {"00000000", "nope"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			if _, err := f.svc.AdminLogin(ctx, tc.dni, tc.pw, "1.1.1.1"); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("got %v", err)
			}
		})
	}

	t.Run("locks after max attempts on the same dni", func(t *testing.T) {
		f := newFixture()
		for i := 0; i < 3; i++ {
			_, _ = f.svc.AdminLogin(ctx, "74455518", "bad", "1.1.1.1")
		}
		// Even the right password is refused while locked.
		_, err := f.svc.AdminLogin(ctx, "74455518", "right-password", "2.2.2.2")
		var tm *TooManyAttemptsError
		if !errors.As(err, &tm) {
			t.Fatalf("got %v", err)
		}
		if tm.RetryAfter != 15*time.Minute {
			t.Fatalf("retry after %v", tm.RetryAfter)
		}

		*f.now = f.now.Add(15*time.Minute + time.Second)
		if _, err := f.svc.AdminLogin(ctx, "74455518", "right-password", "2.2.2.2"); err != nil {
			t.Fatalf("expected unlock after window, got %v", err)
		}
	})

	t.Run("locks per ip across different dnis", func(t *testing.T) {
		f := newFixture()
		for i := 0; i < 5; i++ {
			_, _ = f.svc.AdminLogin(ctx, "dni"+strconv.Itoa(i), "bad", "9.9.9.9")
		}
		_, err := f.svc.AdminLogin(ctx, "74455518", "right-password", "9.9.9.9")
		var tm *TooManyAttemptsError
		if !errors.As(err, &tm) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("success clears the dni counter", func(t *testing.T) {
		f := newFixture()
		_, _ = f.svc.AdminLogin(ctx, "74455518", "bad", "1.1.1.1")
		_, _ = f.svc.AdminLogin(ctx, "74455518", "bad", "1.1.1.1")
		if _, err := f.svc.AdminLogin(ctx, "74455518", "right-password", "1.1.1.1"); err != nil {
			t.Fatal(err)
		}
		if n, _, _ := f.attempts.Failures(ctx, "admin:74455518", time.Time{}); n != 0 {
			t.Fatalf("counter not cleared: %d", n)
		}
	})
}

func login(t *testing.T, f *fixture) Tokens {
	t.Helper()
	tokens, err := f.svc.AdminLogin(context.Background(), "74455518", "right-password", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	return tokens
}

func TestRefresh(t *testing.T) {
	ctx := context.Background()

	t.Run("rotates", func(t *testing.T) {
		f := newFixture()
		first := login(t, f)
		second, err := f.svc.Refresh(ctx, first.RefreshToken)
		if err != nil {
			t.Fatal(err)
		}
		if second.RefreshToken == first.RefreshToken || f.signer.last.Role != RoleSuperadmin {
			t.Fatalf("unexpected: %+v claims %+v", second, f.signer.last)
		}
		if f.refresh.byHash[hashToken(first.RefreshToken)].FamilyID != f.refresh.byHash[hashToken(second.RefreshToken)].FamilyID {
			t.Fatal("family must be preserved")
		}
	})

	t.Run("reuse revokes the whole family", func(t *testing.T) {
		f := newFixture()
		first := login(t, f)
		second, _ := f.svc.Refresh(ctx, first.RefreshToken)
		if _, err := f.svc.Refresh(ctx, first.RefreshToken); !errors.Is(err, ErrInvalidRefreshToken) {
			t.Fatalf("got %v", err)
		}
		// The legitimate newer token is now dead too.
		if _, err := f.svc.Refresh(ctx, second.RefreshToken); !errors.Is(err, ErrInvalidRefreshToken) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		f := newFixture()
		first := login(t, f)
		*f.now = f.now.Add(25 * time.Hour)
		if _, err := f.svc.Refresh(ctx, first.RefreshToken); !errors.Is(err, ErrInvalidRefreshToken) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		if _, err := newFixture().svc.Refresh(ctx, "garbage"); !errors.Is(err, ErrInvalidRefreshToken) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestLogout(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	first := login(t, f)
	second, _ := f.svc.Refresh(ctx, first.RefreshToken)

	if err := f.svc.Logout(ctx, second.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Refresh(ctx, second.RefreshToken); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("got %v", err)
	}
	if err := f.svc.Logout(ctx, "unknown"); err != nil {
		t.Fatalf("unknown token must be ignored, got %v", err)
	}
}

func TestUserLogin(t *testing.T) {
	ctx := context.Background()

	t.Run("success puts tenant and app role in the token", func(t *testing.T) {
		f := newFixture()
		tokens, err := f.svc.UserLogin(ctx, "11111111", "user-password", "olympus", "1.1.1.1")
		if err != nil {
			t.Fatal(err)
		}
		c := f.signer.last
		if tokens.AccessToken != "access-u1" || c.Role != RoleUser || c.System != "olympus" || c.Tenant != "t1" || c.AppRole != "cajero" {
			t.Fatalf("unexpected claims: %+v", c)
		}
		stored := f.refresh.byHash[hashToken(tokens.RefreshToken)]
		if stored.UserID != "u1" || stored.SystemID != "s1" || stored.SystemCode != "olympus" {
			t.Fatalf("unexpected stored token: %+v", stored)
		}
	})

	t.Run("an app role named superadmin never becomes the platform role", func(t *testing.T) {
		f := newFixture()
		f.access.grants["u1|olympus"] = access.Grant{SystemID: "s1", SystemCode: "olympus", TenantID: "t1", Role: "superadmin"}
		if _, err := f.svc.UserLogin(ctx, "11111111", "user-password", "olympus", "1.1.1.1"); err != nil {
			t.Fatal(err)
		}
		if f.signer.last.Role != RoleUser || f.signer.last.AppRole != "superadmin" {
			t.Fatalf("unexpected claims: %+v", f.signer.last)
		}
	})

	for name, tc := range map[string]struct{ dni, pw string }{
		"wrong password":   {"11111111", "nope"},
		"unknown dni":      {"99999999", "user-password"},
		"disabled account": {"22222222", "user-password"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			_, err := f.svc.UserLogin(ctx, tc.dni, tc.pw, "olympus", "1.1.1.1")
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("got %v", err)
			}
			if n, _, _ := f.attempts.Failures(ctx, "dni:"+tc.dni, time.Time{}); n != 1 {
				t.Fatalf("failure not recorded: %d", n)
			}
		})
	}

	t.Run("correct password but no access is forbidden and not counted", func(t *testing.T) {
		f := newFixture()
		for _, system := range []string{"pulso", "does-not-exist"} {
			_, err := f.svc.UserLogin(ctx, "11111111", "user-password", system, "1.1.1.1")
			if !errors.Is(err, access.ErrNoAccess) {
				t.Fatalf("%s: got %v", system, err)
			}
		}
		if n, _, _ := f.attempts.Failures(ctx, "dni:11111111", time.Time{}); n != 0 {
			t.Fatalf("no_access must not count as a failed attempt, got %d", n)
		}
	})

	t.Run("throttled after repeated failures", func(t *testing.T) {
		f := newFixture()
		for i := 0; i < 3; i++ {
			_, _ = f.svc.UserLogin(ctx, "11111111", "bad", "olympus", "1.1.1.1")
		}
		var tm *TooManyAttemptsError
		if _, err := f.svc.UserLogin(ctx, "11111111", "user-password", "olympus", "1.1.1.1"); !errors.As(err, &tm) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("user and admin counters are independent", func(t *testing.T) {
		f := newFixture()
		for i := 0; i < 3; i++ {
			_, _ = f.svc.UserLogin(ctx, "74455518", "bad", "olympus", "1.1.1.1")
		}
		if _, err := f.svc.AdminLogin(ctx, "74455518", "right-password", "2.2.2.2"); err != nil {
			t.Fatalf("admin must not be locked by user attempts: %v", err)
		}
	})
}

func TestUserRefresh(t *testing.T) {
	ctx := context.Background()
	loginUser := func(f *fixture) Tokens {
		tokens, err := f.svc.UserLogin(ctx, "11111111", "user-password", "olympus", "1.1.1.1")
		if err != nil {
			t.Fatal(err)
		}
		return tokens
	}

	t.Run("keeps system and refreshes the claims", func(t *testing.T) {
		f := newFixture()
		first := loginUser(f)
		f.access.grants["u1|olympus"] = access.Grant{SystemID: "s1", SystemCode: "olympus", TenantID: "t1", Role: "admin"}
		if _, err := f.svc.Refresh(ctx, first.RefreshToken); err != nil {
			t.Fatal(err)
		}
		c := f.signer.last
		if c.Role != RoleUser || c.System != "olympus" || c.AppRole != "admin" {
			t.Fatalf("role change not picked up: %+v", c)
		}
	})

	t.Run("removed access ends the session", func(t *testing.T) {
		f := newFixture()
		first := loginUser(f)
		delete(f.access.grants, "u1|olympus")
		if _, err := f.svc.Refresh(ctx, first.RefreshToken); !errors.Is(err, ErrInvalidRefreshToken) {
			t.Fatalf("got %v", err)
		}
		if f.refresh.byHash[hashToken(first.RefreshToken)].RevokedAt == nil {
			t.Fatal("family must be revoked")
		}
	})

	t.Run("disabled account ends the session", func(t *testing.T) {
		f := newFixture()
		first := loginUser(f)
		u := f.users.byDNI["11111111"]
		u.Status = user.StatusDisabled
		f.users.byDNI["11111111"] = u
		if _, err := f.svc.Refresh(ctx, first.RefreshToken); !errors.Is(err, ErrInvalidRefreshToken) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("deleted user ends the session", func(t *testing.T) {
		f := newFixture()
		first := loginUser(f)
		delete(f.users.byDNI, "11111111")
		if _, err := f.svc.Refresh(ctx, first.RefreshToken); !errors.Is(err, ErrInvalidRefreshToken) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestPendingPasswordBlocksLogin(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	_, err := f.svc.UserLogin(ctx, "33333333", "33333333", "olympus", "1.1.1.1")
	if !errors.Is(err, ErrPasswordChangeRequired) {
		t.Fatalf("got %v", err)
	}
	if f.signer.last.Subject != "" {
		t.Fatal("no token may be signed while the password change is pending")
	}
	// Reported even for a system the user cannot enter: access is never revealed before the change.
	if _, err := f.svc.UserLogin(ctx, "33333333", "33333333", "nova", "1.1.1.1"); !errors.Is(err, ErrPasswordChangeRequired) {
		t.Fatalf("got %v", err)
	}
	if _, err := f.svc.UserLogin(ctx, "33333333", "wrong", "olympus", "1.1.1.1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("got %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	ctx := context.Background()

	t.Run("first login flow", func(t *testing.T) {
		f := newFixture()
		if err := f.svc.ChangePassword(ctx, "33333333", "33333333", "my-new-password", "1.1.1.1"); err != nil {
			t.Fatal(err)
		}
		u := f.users.byDNI["33333333"]
		if u.PasswordHash != "my-new-password" || u.MustChangePassword {
			t.Fatalf("unexpected user: %+v", u)
		}
		if _, err := f.svc.UserLogin(ctx, "33333333", "33333333", "olympus", "1.1.1.1"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("old password must stop working, got %v", err)
		}
		if _, err := f.svc.UserLogin(ctx, "33333333", "my-new-password", "olympus", "1.1.1.1"); err != nil {
			t.Fatalf("login with the new password: %v", err)
		}
	})

	t.Run("ends every session", func(t *testing.T) {
		f := newFixture()
		first, err := f.svc.UserLogin(ctx, "11111111", "user-password", "olympus", "1.1.1.1")
		if err != nil {
			t.Fatal(err)
		}
		if err := f.svc.ChangePassword(ctx, "11111111", "user-password", "another-password", "1.1.1.1"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.svc.Refresh(ctx, first.RefreshToken); !errors.Is(err, ErrInvalidRefreshToken) {
			t.Fatalf("got %v", err)
		}
	})

	for name, tc := range map[string]struct{ next string }{
		"too short":       {"short"},
		"the dni":         {"11111111"},
		"same as current": {"user-password"},
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			f := newFixture()
			if err := f.svc.ChangePassword(ctx, "11111111", "user-password", tc.next, "1.1.1.1"); !errors.Is(err, user.ErrWeakPassword) {
				t.Fatalf("got %v", err)
			}
		})
	}

	t.Run("wrong current password is a counted failure", func(t *testing.T) {
		f := newFixture()
		if err := f.svc.ChangePassword(ctx, "11111111", "nope", "my-new-password", "1.1.1.1"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("got %v", err)
		}
		if n, _, _ := f.attempts.Failures(ctx, "dni:11111111", time.Time{}); n != 1 {
			t.Fatalf("failure not recorded: %d", n)
		}
	})

	t.Run("unknown and disabled accounts look like wrong credentials", func(t *testing.T) {
		f := newFixture()
		for _, dni := range []string{"99999999", "22222222"} {
			if err := f.svc.ChangePassword(ctx, dni, "user-password", "my-new-password", "1.1.1.1"); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("%s: got %v", dni, err)
			}
		}
	})

	t.Run("throttled", func(t *testing.T) {
		f := newFixture()
		for i := 0; i < 3; i++ {
			_ = f.svc.ChangePassword(ctx, "11111111", "bad", "my-new-password", "1.1.1.1")
		}
		var tm *TooManyAttemptsError
		if err := f.svc.ChangePassword(ctx, "11111111", "user-password", "my-new-password", "1.1.1.1"); !errors.As(err, &tm) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestRefreshDeniedWhilePasswordChangePending(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	first, _ := f.svc.UserLogin(ctx, "11111111", "user-password", "olympus", "1.1.1.1")
	u := f.users.byDNI["11111111"]
	u.MustChangePassword = true
	f.users.byDNI["11111111"] = u
	if _, err := f.svc.Refresh(ctx, first.RefreshToken); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("got %v", err)
	}
}

func TestRevokeUserSessions(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	first, _ := f.svc.UserLogin(ctx, "11111111", "user-password", "olympus", "1.1.1.1")
	if err := f.svc.RevokeUserSessions(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Refresh(ctx, first.RefreshToken); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("got %v", err)
	}
}
