package tenant

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

type CreateInput struct {
	RUC       string
	LegalName string
	TradeName string
}

func (s *Service) Create(ctx context.Context, in CreateInput) (Tenant, error) {
	if !validRUC(in.RUC) {
		return Tenant{}, ErrInvalidRUC
	}
	legal := normalizeName(in.LegalName)
	if legal == "" {
		return Tenant{}, ErrInvalidLegalName
	}
	created, err := s.repo.Create(ctx, Tenant{
		RUC: in.RUC, LegalName: legal, TradeName: normalizeName(in.TradeName), Status: StatusActive,
	})
	if err != nil {
		return Tenant{}, fmt.Errorf("create tenant: %w", err)
	}
	return created, nil
}

func (s *Service) Get(ctx context.Context, id string) (Tenant, error) {
	if !platform.IsUUID(id) {
		return Tenant{}, ErrInvalidID
	}
	t, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return Tenant{}, fmt.Errorf("get tenant: %w", err)
	}
	return t, nil
}

func (s *Service) List(ctx context.Context) ([]Tenant, error) {
	ts, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	return ts, nil
}

// ListForSystem returns the tenants a system serves: the ones that have it enabled and are active.
func (s *Service) ListForSystem(ctx context.Context, systemCode string) ([]Tenant, error) {
	if systemCode == "" {
		return nil, ErrSystemNotFound
	}
	ts, err := s.repo.ListForSystem(ctx, systemCode)
	if err != nil {
		return nil, fmt.Errorf("list tenants of system: %w", err)
	}
	return ts, nil
}

// EnableSystem records that the tenant has contracted the system.
func (s *Service) EnableSystem(ctx context.Context, tenantID, systemID string) error {
	if !platform.IsUUID(tenantID) || !platform.IsUUID(systemID) {
		return ErrInvalidID
	}
	if err := s.repo.EnableSystem(ctx, tenantID, systemID); err != nil {
		return fmt.Errorf("enable system: %w", err)
	}
	return nil
}

// DisableSystem removes the system from the tenant. Every access its users had in that system is removed with it.
func (s *Service) DisableSystem(ctx context.Context, tenantID, systemID string) error {
	if !platform.IsUUID(tenantID) || !platform.IsUUID(systemID) {
		return ErrInvalidID
	}
	if err := s.repo.DisableSystem(ctx, tenantID, systemID); err != nil {
		return fmt.Errorf("disable system: %w", err)
	}
	return nil
}
