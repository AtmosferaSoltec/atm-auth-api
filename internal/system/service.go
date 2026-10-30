package system

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

func (s *Service) List(ctx context.Context) ([]System, error) {
	systems, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list systems: %w", err)
	}
	return systems, nil
}

// UpdateSession sets how long users stay signed in to the system. Sessions already open pick the new policy
// the next time they are refreshed.
func (s *Service) UpdateSession(ctx context.Context, id, mode string) (System, error) {
	if !platform.IsUUID(id) {
		return System{}, ErrInvalidID
	}
	if mode == "" {
		return System{}, ErrInvalidSessionMode
	}
	mode, err := normalizeSession(mode)
	if err != nil {
		return System{}, err
	}
	updated, err := s.repo.UpdateSession(ctx, id, mode)
	if err != nil {
		return System{}, fmt.Errorf("update system session: %w", err)
	}
	return updated, nil
}
