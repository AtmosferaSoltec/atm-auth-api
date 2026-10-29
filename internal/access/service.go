package access

import (
	"context"
	"fmt"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

type Service struct {
	repo Repository
}

func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

type AssignInput struct {
	UserID      string
	SystemID    string
	TenantID    string
	Role        string
	ManageUsers bool
}

// Assign lets a user enter a system inside a tenant. A user can be in only one tenant per system:
// to move them, Remove the old access first.
func (s *Service) Assign(ctx context.Context, in AssignInput) (Access, error) {
	if !platform.IsUUID(in.UserID) || !platform.IsUUID(in.SystemID) || !platform.IsUUID(in.TenantID) {
		return Access{}, ErrInvalidID
	}
	role, ok := normalizeRole(in.Role)
	if !ok {
		return Access{}, ErrInvalidRole
	}
	a, err := s.repo.Assign(ctx, Access{UserID: in.UserID, SystemID: in.SystemID, TenantID: in.TenantID, Role: role, ManageUsers: in.ManageUsers})
	if err != nil {
		return Access{}, fmt.Errorf("assign access: %w", err)
	}
	return a, nil
}

func (s *Service) Remove(ctx context.Context, userID, systemID string) error {
	if !platform.IsUUID(userID) || !platform.IsUUID(systemID) {
		return ErrInvalidID
	}
	if err := s.repo.Remove(ctx, userID, systemID); err != nil {
		return fmt.Errorf("remove access: %w", err)
	}
	return nil
}

// Resolve returns the user's current grant for a system, or ErrNoAccess.
func (s *Service) Resolve(ctx context.Context, userID, systemCode string) (Grant, error) {
	g, err := s.repo.Resolve(ctx, userID, systemCode)
	if err != nil {
		return Grant{}, fmt.Errorf("resolve access: %w", err)
	}
	return g, nil
}

// ListByUser returns every access of a user.
func (s *Service) ListByUser(ctx context.Context, userID string) ([]Detail, error) {
	if !platform.IsUUID(userID) {
		return nil, ErrInvalidID
	}
	out, err := s.repo.ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list access: %w", err)
	}
	return out, nil
}
