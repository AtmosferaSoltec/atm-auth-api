package catalog

import (
	"context"
	"fmt"
)

type Service struct {
	repo    Repository
	systems []System
}

// NewService syncs the given catalog; use Systems in production.
func NewService(repo Repository, systems []System) *Service {
	return &Service{repo: repo, systems: systems}
}

// Sync makes the database hold at least the catalog, and reports what the database has beyond it.
// It is idempotent and safe to run on every start.
func (s *Service) Sync(ctx context.Context) (Orphans, error) {
	if err := s.repo.Upsert(ctx, s.systems); err != nil {
		return Orphans{}, fmt.Errorf("sync catalog: %w", err)
	}
	orphans, err := s.repo.FindOrphans(ctx, s.systems)
	if err != nil {
		return Orphans{}, fmt.Errorf("find catalog orphans: %w", err)
	}
	return orphans, nil
}
