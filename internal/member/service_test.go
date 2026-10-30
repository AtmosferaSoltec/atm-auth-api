package member

import (
	"context"
	"errors"
	"testing"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/access"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/user"
)

const (
	sysID    = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	tenantID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	owner    = "11111111-1111-1111-1111-111111111111"
	cashier  = "22222222-2222-2222-2222-222222222222"
	other    = "33333333-3333-3333-3333-333333333333"
	manager2 = "44444444-4444-4444-4444-444444444444"
)

var scope = Scope{ManagerID: owner, SystemID: sysID, SystemCode: "olympus", TenantID: tenantID}

type fakeRepo struct {
	members   map[string]Member // by user id, all in the scope
	onlyHere  map[string]bool
	updated   map[string]string
	removed   []string
	unchanged bool // make UpdateRole/Remove report "no row changed"
	roles     []RoleOption
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		members: map[string]Member{
			owner:    {UserID: owner, Role: "dueño", ManageUsers: true},
			manager2: {UserID: manager2, Role: "dueño", ManageUsers: true},
			cashier:  {UserID: cashier, Role: "cajero"},
		},
		onlyHere: map[string]bool{cashier: true},
		updated:  map[string]string{},
	}
}

func (f *fakeRepo) List(context.Context, string, string) ([]Member, error) { return nil, nil }
func (f *fakeRepo) Get(_ context.Context, _, _, id string) (Member, error) {
	if m, ok := f.members[id]; ok {
		return m, nil
	}
	return Member{}, ErrMemberNotFound
}
func (f *fakeRepo) UpdateRole(_ context.Context, _, _, id, role string) (bool, error) {
	f.updated[id] = role
	return !f.unchanged, nil
}
func (f *fakeRepo) Remove(_ context.Context, _, _, id string) (bool, error) {
	f.removed = append(f.removed, id)
	return !f.unchanged, nil
}
func (f *fakeRepo) Roles(context.Context, string) ([]RoleOption, error) { return f.roles, nil }

func (f *fakeRepo) SystemFor(_ context.Context, code, tenant string) (string, error) {
	if code == "olympus" && tenant == tenantID {
		return sysID, nil
	}
	return "", ErrTenantNotServed
}

func (f *fakeRepo) OnlyInTenant(_ context.Context, id, _ string) (bool, error) {
	return f.onlyHere[id], nil
}

type fakeFinder struct{ users map[string]user.User }

func (f fakeFinder) GetByDNI(_ context.Context, dni string) (user.User, error) {
	for _, u := range f.users {
		if u.DNI == dni {
			return u, nil
		}
	}
	return user.User{}, user.ErrUserNotFound
}
func (f fakeFinder) GetByID(_ context.Context, id string) (user.User, error) {
	if u, ok := f.users[id]; ok {
		return u, nil
	}
	return user.User{}, user.ErrUserNotFound
}

type fakeUsers struct {
	created []user.CreateInput
	reset   []string
}

func (f *fakeUsers) Create(_ context.Context, in user.CreateInput) (user.User, error) {
	f.created = append(f.created, in)
	if in.FullName == "" {
		return user.User{}, user.ErrInvalidName
	}
	return user.User{ID: "new-" + in.DNI, DNI: in.DNI, FullName: in.FullName}, nil
}
func (f *fakeUsers) ResetPassword(_ context.Context, id string) error {
	f.reset = append(f.reset, id)
	return nil
}

type fakeAccess struct {
	assigned []access.AssignInput
	grants   map[string]access.Grant
	err      error
}

func (f *fakeAccess) Assign(_ context.Context, in access.AssignInput) (access.Access, error) {
	if f.err != nil {
		return access.Access{}, f.err
	}
	f.assigned = append(f.assigned, in)
	return access.Access{}, nil
}
func (f *fakeAccess) Options(_ context.Context, userID, _ string) ([]access.Option, error) {
	if g, ok := f.grants[userID]; ok {
		return []access.Option{{TenantID: g.TenantID}}, nil
	}
	return nil, nil
}
func (f *fakeAccess) Resolve(_ context.Context, userID, _, _ string) (access.Grant, error) {
	if g, ok := f.grants[userID]; ok {
		return g, nil
	}
	return access.Grant{}, access.ErrNoAccess
}

type fixture struct {
	svc    *Service
	repo   *fakeRepo
	users  *fakeUsers
	access *fakeAccess
	finder fakeFinder
}

func newFixture() *fixture {
	f := &fixture{repo: newFakeRepo(), users: &fakeUsers{}}
	f.finder = fakeFinder{users: map[string]user.User{
		owner:   {ID: owner, DNI: "44444444", Status: user.StatusActive},
		other:   {ID: other, DNI: "55555555", FullName: "Existing Person", Status: user.StatusActive},
		cashier: {ID: cashier, DNI: "66666666", Status: user.StatusActive},
	}}
	f.access = &fakeAccess{grants: map[string]access.Grant{
		owner:   {SystemID: sysID, SystemCode: "olympus", TenantID: tenantID, ManageUsers: true},
		cashier: {SystemID: sysID, SystemCode: "olympus", TenantID: tenantID},
	}}
	f.svc = NewService(f.repo, f.finder, f.users, f.access)
	return f
}

func TestAuthorize(t *testing.T) {
	ctx := context.Background()

	t.Run("owner gets the scope from the database grant", func(t *testing.T) {
		sc, err := newFixture().svc.Authorize(ctx, owner, "olympus", tenantID)
		if err != nil || sc != scope {
			t.Fatalf("got %+v err %v", sc, err)
		}
	})

	cases := map[string]func(f *fixture){
		"regular member":   func(f *fixture) {},
		"pending password": func(f *fixture) { u := f.finder.users[owner]; u.MustChangePassword = true; f.finder.users[owner] = u },
		"disabled account": func(f *fixture) {
			u := f.finder.users[owner]
			u.Status = user.StatusDisabled
			f.finder.users[owner] = u
		},
		"deleted account":    func(f *fixture) { delete(f.finder.users, owner) },
		"access removed":     func(f *fixture) { delete(f.access.grants, owner) },
		"permission revoked": func(f *fixture) { g := f.access.grants[owner]; g.ManageUsers = false; f.access.grants[owner] = g },
	}
	for name, mutate := range cases {
		t.Run("denied: "+name, func(t *testing.T) {
			f := newFixture()
			mutate(f)
			who := owner
			if name == "regular member" {
				who = cashier
			}
			if _, err := f.svc.Authorize(ctx, who, "olympus", tenantID); !errors.Is(err, ErrNotManager) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestAdd(t *testing.T) {
	ctx := context.Background()

	t.Run("new person: account created with the DNI as initial password, never as manager", func(t *testing.T) {
		f := newFixture()
		f.repo.members["new-77777777"] = Member{UserID: "new-77777777", Role: "cajero"}
		if _, err := f.svc.Add(ctx, scope, AddInput{DNI: "77777777", FullName: "Nueva Persona", Role: " cajero "}); err != nil {
			t.Fatal(err)
		}
		if len(f.users.created) != 1 || f.users.created[0].Password != "" || f.users.created[0].FullName != "Nueva Persona" {
			t.Fatalf("unexpected create: %+v", f.users.created)
		}
		a := f.access.assigned[0]
		if a.SystemID != sysID || a.TenantID != tenantID || a.Role != "cajero" || a.ManageUsers {
			t.Fatalf("unexpected access: %+v", a)
		}
	})

	t.Run("existing person: account untouched, only access added", func(t *testing.T) {
		f := newFixture()
		f.repo.members[other] = Member{UserID: other, Role: "cajero"}
		if _, err := f.svc.Add(ctx, scope, AddInput{DNI: "55555555", FullName: "Ignored Name", Role: "cajero"}); err != nil {
			t.Fatal(err)
		}
		if len(f.users.created) != 0 {
			t.Fatalf("must not create an account: %+v", f.users.created)
		}
		if f.access.assigned[0].UserID != other {
			t.Fatalf("unexpected access: %+v", f.access.assigned)
		}
	})

	t.Run("validation happens before any account is created", func(t *testing.T) {
		f := newFixture()
		for name, in := range map[string]AddInput{
			"bad dni":    {DNI: "123", FullName: "X", Role: "cajero"},
			"empty role": {DNI: "77777777", FullName: "X", Role: "  "},
		} {
			if _, err := f.svc.Add(ctx, scope, in); err == nil {
				t.Fatalf("%s: expected error", name)
			}
		}
		if len(f.users.created) != 0 {
			t.Fatalf("an account was created despite invalid input: %+v", f.users.created)
		}
	})

	t.Run("new person without a name", func(t *testing.T) {
		if _, err := newFixture().svc.Add(ctx, scope, AddInput{DNI: "77777777", Role: "cajero"}); !errors.Is(err, user.ErrInvalidName) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("already in another organization of this system", func(t *testing.T) {
		f := newFixture()
		f.access.err = access.ErrUserAlreadyInSystem
		if _, err := f.svc.Add(ctx, scope, AddInput{DNI: "55555555", Role: "cajero"}); !errors.Is(err, access.ErrUserAlreadyInSystem) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestOnlyTheReservedRoleIsProtected(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	f.repo.members[other] = Member{UserID: other, Role: "superadmin"}

	// Someone who used to be an owner is an ordinary member now: the system decides who manages whom.
	if err := f.svc.UpdateRole(ctx, scope, manager2, "cajero"); err != nil {
		t.Fatalf("a former owner must be editable: %v", err)
	}
	if err := f.svc.Remove(ctx, scope, owner); err != nil {
		t.Fatalf("a former owner must be removable: %v", err)
	}
	if err := f.svc.ResetPassword(ctx, scope, other); !errors.Is(err, ErrProtectedMember) {
		t.Fatalf("the reserved role must stay protected: %v", err)
	}
	if len(f.users.reset) != 0 {
		t.Fatal("a protected member was modified")
	}
}

func TestMemberOperations(t *testing.T) {
	ctx := context.Background()

	t.Run("update role", func(t *testing.T) {
		f := newFixture()
		if err := f.svc.UpdateRole(ctx, scope, cashier, " supervisor "); err != nil {
			t.Fatal(err)
		}
		if f.repo.updated[cashier] != "supervisor" {
			t.Fatalf("got %v", f.repo.updated)
		}
		if err := f.svc.UpdateRole(ctx, scope, cashier, ""); !errors.Is(err, access.ErrInvalidRole) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("not a member of this tenant", func(t *testing.T) {
		f := newFixture()
		if err := f.svc.Remove(ctx, scope, other); !errors.Is(err, ErrMemberNotFound) {
			t.Fatalf("got %v", err)
		}
		if err := f.svc.Remove(ctx, scope, "not-a-uuid"); !errors.Is(err, ErrInvalidID) {
			t.Fatalf("got %v", err)
		}
		if len(f.repo.removed) != 0 {
			t.Fatal("nothing may be removed")
		}
	})

	t.Run("remove", func(t *testing.T) {
		f := newFixture()
		if err := f.svc.Remove(ctx, scope, cashier); err != nil || len(f.repo.removed) != 1 {
			t.Fatalf("got %v %v", err, f.repo.removed)
		}
	})

	t.Run("a row that vanished meanwhile is reported", func(t *testing.T) {
		f := newFixture()
		f.repo.unchanged = true
		if err := f.svc.Remove(ctx, scope, cashier); !errors.Is(err, ErrMemberNotFound) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestResetPassword(t *testing.T) {
	ctx := context.Background()

	t.Run("only member of this tenant", func(t *testing.T) {
		f := newFixture()
		if err := f.svc.ResetPassword(ctx, scope, cashier); err != nil {
			t.Fatal(err)
		}
		if len(f.users.reset) != 1 || f.users.reset[0] != cashier {
			t.Fatalf("got %v", f.users.reset)
		}
	})

	t.Run("also belongs to another organization", func(t *testing.T) {
		f := newFixture()
		f.repo.onlyHere[cashier] = false
		if err := f.svc.ResetPassword(ctx, scope, cashier); !errors.Is(err, ErrResetNotAllowed) {
			t.Fatalf("got %v", err)
		}
		if len(f.users.reset) != 0 {
			t.Fatal("password was reset anyway")
		}
	})
}

func TestReservedRole(t *testing.T) {
	ctx := context.Background()

	t.Run("an owner cannot give the superadmin role, however it is spelled", func(t *testing.T) {
		for _, role := range []string{"superadmin", "SuperAdmin", " SUPERADMIN "} {
			f := newFixture()
			if _, err := f.svc.Add(ctx, scope, AddInput{DNI: "77777777", FullName: "Nueva", Role: role}); !errors.Is(err, access.ErrUnknownRole) {
				t.Fatalf("add %q: got %v", role, err)
			}
			if len(f.users.created) != 0 || len(f.access.assigned) != 0 {
				t.Fatalf("nothing may be created for %q: %+v %+v", role, f.users.created, f.access.assigned)
			}
			if err := f.svc.UpdateRole(ctx, scope, cashier, role); !errors.Is(err, access.ErrUnknownRole) {
				t.Fatalf("update %q: got %v", role, err)
			}
			if len(f.repo.updated) != 0 {
				t.Fatalf("the role must not change for %q: %+v", role, f.repo.updated)
			}
		}
	})

	t.Run("the role is not offered to owners", func(t *testing.T) {
		f := newFixture()
		f.repo.roles = []RoleOption{{Name: "admin"}, {Name: "superadmin"}, {Name: "cashier"}}
		got, err := f.svc.Roles(ctx, scope)
		if err != nil || len(got) != 2 || got[0].Name != "admin" || got[1].Name != "cashier" {
			t.Fatalf("got %+v err %v", got, err)
		}
	})

	t.Run("an owner cannot change or remove someone who already has it", func(t *testing.T) {
		f := newFixture()
		f.repo.members[other] = Member{UserID: other, Role: "superadmin"}
		if err := f.svc.UpdateRole(ctx, scope, other, "cajero"); !errors.Is(err, ErrProtectedMember) {
			t.Fatalf("got %v", err)
		}
		if err := f.svc.Remove(ctx, scope, other); !errors.Is(err, ErrProtectedMember) {
			t.Fatalf("got %v", err)
		}
	})
}

// A person who owns two companies manages the members of the one their token works for, never the other's.
func TestAuthorizeUsesTheCompanyOfTheToken(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	f.access.grants[owner] = access.Grant{SystemID: sysID, SystemCode: "olympus", TenantID: "other-tenant", ManageUsers: true}

	// The resolver answers for the company asked for; the scope carries that company.
	sc, err := f.svc.Authorize(ctx, owner, "olympus", "other-tenant")
	if err != nil || sc.TenantID != "other-tenant" {
		t.Fatalf("got %+v err %v", sc, err)
	}
	// A token without a company never manages anyone.
	if _, err := f.svc.Authorize(ctx, owner, "olympus", ""); !errors.Is(err, ErrNotManager) {
		t.Fatalf("got %v", err)
	}
}

// Putting a customer's staff inside another customer's company is not something an owner can do.
func TestAddRefusesSomeoneOfAnotherCompany(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	f.access.grants[other] = access.Grant{SystemID: sysID, SystemCode: "olympus", TenantID: "another-company"}

	_, err := f.svc.Add(ctx, scope, AddInput{DNI: "55555555", Role: "cajero"})
	if !errors.Is(err, access.ErrUserAlreadyInSystem) {
		t.Fatalf("got %v", err)
	}
	if len(f.access.assigned) != 0 {
		t.Fatalf("assigned %+v", f.access.assigned)
	}
}

func TestScopeFor(t *testing.T) {
	ctx := context.Background()
	f := newFixture()

	sc, err := f.svc.ScopeFor(ctx, "olympus", tenantID)
	if err != nil || sc.SystemID != sysID || sc.TenantID != tenantID || sc.SystemCode != "olympus" {
		t.Fatalf("got %+v err %v", sc, err)
	}
	for name, tc := range map[string]struct{ system, tenant string }{
		"a bad tenant id":             {"olympus", "nope"},
		"no system":                   {"", tenantID},
		"a system that is not served": {"pulso", tenantID},
		"another tenant":              {"olympus", "cccccccc-cccc-cccc-cccc-cccccccccccc"},
	} {
		if _, err := f.svc.ScopeFor(ctx, tc.system, tc.tenant); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}
	if _, err := f.svc.ScopeFor(ctx, "pulso", tenantID); !errors.Is(err, ErrTenantNotServed) {
		t.Fatalf("got %v", err)
	}
}
