package member

import (
	"context"
	"errors"
	"fmt"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/access"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/user"
)

type UserFinder interface {
	GetByDNI(ctx context.Context, dni string) (user.User, error)
	GetByID(ctx context.Context, id string) (user.User, error)
}

type UserManager interface {
	Create(ctx context.Context, in user.CreateInput) (user.User, error)
	ResetPassword(ctx context.Context, id string) error
}

type AccessManager interface {
	Assign(ctx context.Context, in access.AssignInput) (access.Access, error)
	Resolve(ctx context.Context, userID, systemCode string) (access.Grant, error)
}

type Service struct {
	repo   Repository
	finder UserFinder
	users  UserManager
	access AccessManager
}

func NewService(repo Repository, finder UserFinder, users UserManager, accessMgr AccessManager) *Service {
	return &Service{repo: repo, finder: finder, users: users, access: accessMgr}
}

// Authorize turns an authenticated user into a Scope. It reads the database, not the token, so a revoked
// permission stops working immediately.
func (s *Service) Authorize(ctx context.Context, userID, systemCode string) (Scope, error) {
	u, err := s.finder.GetByID(ctx, userID)
	if errors.Is(err, user.ErrUserNotFound) {
		return Scope{}, ErrNotManager
	}
	if err != nil {
		return Scope{}, fmt.Errorf("authorize manager: %w", err)
	}
	if u.Status != user.StatusActive || u.MustChangePassword {
		return Scope{}, ErrNotManager
	}
	g, err := s.access.Resolve(ctx, userID, systemCode)
	if errors.Is(err, access.ErrNoAccess) {
		return Scope{}, ErrNotManager
	}
	if err != nil {
		return Scope{}, fmt.Errorf("authorize manager: %w", err)
	}
	if !g.ManageUsers {
		return Scope{}, ErrNotManager
	}
	return Scope{ManagerID: userID, SystemID: g.SystemID, SystemCode: g.SystemCode, TenantID: g.TenantID}, nil
}

func (s *Service) List(ctx context.Context, sc Scope) ([]Member, error) {
	members, err := s.repo.List(ctx, sc.SystemID, sc.TenantID)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	return members, nil
}

type AddInput struct {
	DNI      string
	FullName string
	Role     string
}

// Add gives a person access to the scope's system and tenant. If the DNI has no account yet, one is created
// with the DNI as initial password. If it already exists, the account (name and password) is left untouched.
func (s *Service) Add(ctx context.Context, sc Scope, in AddInput) (Member, error) {
	if !user.ValidDNI(in.DNI) {
		return Member{}, user.ErrInvalidDNI
	}
	role, ok := access.NormalizeRole(in.Role)
	if !ok {
		return Member{}, access.ErrInvalidRole
	}

	u, err := s.finder.GetByDNI(ctx, in.DNI)
	if errors.Is(err, user.ErrUserNotFound) {
		u, err = s.users.Create(ctx, user.CreateInput{DNI: in.DNI, FullName: in.FullName})
		if errors.Is(err, user.ErrDNITaken) { // created concurrently
			u, err = s.finder.GetByDNI(ctx, in.DNI)
		}
	}
	if err != nil {
		return Member{}, fmt.Errorf("add member: %w", err)
	}

	// Never grants manage_users: only the superadmin does.
	if _, err := s.access.Assign(ctx, access.AssignInput{
		UserID: u.ID, SystemID: sc.SystemID, TenantID: sc.TenantID, Role: role,
	}); err != nil {
		return Member{}, fmt.Errorf("add member: %w", err)
	}
	m, err := s.repo.Get(ctx, sc.SystemID, sc.TenantID, u.ID)
	if err != nil {
		return Member{}, fmt.Errorf("add member: %w", err)
	}
	return m, nil
}

// editable returns the member if the owner may change it: it must belong to the scope and not be an owner.
func (s *Service) editable(ctx context.Context, sc Scope, userID string) (Member, error) {
	if !platform.IsUUID(userID) {
		return Member{}, ErrInvalidID
	}
	m, err := s.repo.Get(ctx, sc.SystemID, sc.TenantID, userID)
	if err != nil {
		return Member{}, err
	}
	if m.ManageUsers {
		return Member{}, ErrProtectedMember
	}
	return m, nil
}

func (s *Service) UpdateRole(ctx context.Context, sc Scope, userID, role string) error {
	role, ok := access.NormalizeRole(role)
	if !ok {
		return access.ErrInvalidRole
	}
	if _, err := s.editable(ctx, sc, userID); err != nil {
		return err
	}
	changed, err := s.repo.UpdateRole(ctx, sc.SystemID, sc.TenantID, userID, role)
	if err != nil {
		return fmt.Errorf("update member role: %w", err)
	}
	if !changed {
		return ErrMemberNotFound
	}
	return nil
}

// Remove takes the member out of the scope's tenant. The account itself is never disabled or deleted here.
func (s *Service) Remove(ctx context.Context, sc Scope, userID string) error {
	if _, err := s.editable(ctx, sc, userID); err != nil {
		return err
	}
	changed, err := s.repo.Remove(ctx, sc.SystemID, sc.TenantID, userID)
	if err != nil {
		return fmt.Errorf("remove member: %w", err)
	}
	if !changed {
		return ErrMemberNotFound
	}
	return nil
}

// ResetPassword is allowed only for people who exist solely in the owner's tenant. Otherwise the owner would
// gain control of an account that also works in other organizations.
func (s *Service) ResetPassword(ctx context.Context, sc Scope, userID string) error {
	if _, err := s.editable(ctx, sc, userID); err != nil {
		return err
	}
	only, err := s.repo.OnlyInTenant(ctx, userID, sc.TenantID)
	if err != nil {
		return fmt.Errorf("reset member password: %w", err)
	}
	if !only {
		return ErrResetNotAllowed
	}
	if err := s.users.ResetPassword(ctx, userID); err != nil {
		return fmt.Errorf("reset member password: %w", err)
	}
	return nil
}

// Roles returns the roles of the owner's system, to choose from when adding or changing a member.
func (s *Service) Roles(ctx context.Context, sc Scope) ([]RoleOption, error) {
	roles, err := s.repo.Roles(ctx, sc.SystemID)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	return roles, nil
}
