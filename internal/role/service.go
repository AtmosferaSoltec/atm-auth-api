package role

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
