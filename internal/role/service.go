package role

import (
	"context"
	"fmt"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/access"
	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

type Service struct {
	repo Repository
}

func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

type CreateInput struct {
	SystemID    string
	Name        string
	Description string
}

// Create adds a role to the system's catalog. The name never changes afterwards: systems compare roles by it.
func (s *Service) Create(ctx context.Context, in CreateInput) (Role, error) {
	if !platform.IsUUID(in.SystemID) {
		return Role{}, ErrInvalidID
	}
	name, ok := access.NormalizeRole(in.Name)
	if !ok {
		return Role{}, ErrInvalidName
	}
	description, ok := normalizeDescription(in.Description)
	if !ok {
		return Role{}, ErrInvalidDescription
	}
	created, err := s.repo.Create(ctx, Role{SystemID: in.SystemID, Name: name, Description: description})
	if err != nil {
		return Role{}, fmt.Errorf("create role: %w", err)
	}
	return created, nil
}

func (s *Service) List(ctx context.Context, systemID string) ([]Role, error) {
	if !platform.IsUUID(systemID) {
		return nil, ErrInvalidID
	}
	roles, err := s.repo.List(ctx, systemID)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	return roles, nil
}

func (s *Service) UpdateDescription(ctx context.Context, systemID, roleID, description string) (Role, error) {
	if !platform.IsUUID(systemID) || !platform.IsUUID(roleID) {
		return Role{}, ErrInvalidID
	}
	description, ok := normalizeDescription(description)
	if !ok {
		return Role{}, ErrInvalidDescription
	}
	updated, err := s.repo.UpdateDescription(ctx, systemID, roleID, description)
	if err != nil {
		return Role{}, fmt.Errorf("update role: %w", err)
	}
	return updated, nil
}

// Delete removes a role nobody has. A role in use returns ErrRoleInUse.
func (s *Service) Delete(ctx context.Context, systemID, roleID string) error {
	if !platform.IsUUID(systemID) || !platform.IsUUID(roleID) {
		return ErrInvalidID
	}
	if err := s.repo.Delete(ctx, systemID, roleID); err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	return nil
}
