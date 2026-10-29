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

type CreateInput struct {
	Code string
	Name string
	// SessionMode defaults to SessionPersistent when empty. SessionMinutes only applies to SessionTemporary.
	SessionMode    string
	SessionMinutes int
}

func (s *Service) Create(ctx context.Context, in CreateInput) (System, error) {
	if !validCode(in.Code) {
		return System{}, ErrInvalidCode
	}
	name := normalizeName(in.Name)
	if name == "" {
		return System{}, ErrInvalidName
	}
	mode, minutes, err := normalizeSession(in.SessionMode, in.SessionMinutes)
	if err != nil {
		return System{}, err
	}
	created, err := s.repo.Create(ctx, System{Code: in.Code, Name: name, Status: StatusActive, SessionMode: mode, SessionMinutes: minutes})
	if err != nil {
		return System{}, fmt.Errorf("create system: %w", err)
	}
	return created, nil
}

func (s *Service) List(ctx context.Context) ([]System, error) {
	systems, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list systems: %w", err)
	}
	return systems, nil
}

// Delete removes a system for good, with everything that depends on it. The caller must repeat the system's code
// as confirmation; a different code returns ErrCodeMismatch and nothing is deleted.
func (s *Service) Delete(ctx context.Context, id, confirmCode string) error {
	if !platform.IsUUID(id) {
		return ErrInvalidID
	}
	sys, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("delete system: %w", err)
	}
	if confirmCode != sys.Code {
		return ErrCodeMismatch
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete system: %w", err)
	}
	return nil
}

// UpdateSession sets how long users stay signed in to the system. Sessions already open pick the new policy
// the next time they are refreshed.
func (s *Service) UpdateSession(ctx context.Context, id, mode string, minutes int) (System, error) {
	if !platform.IsUUID(id) {
		return System{}, ErrInvalidID
	}
	if mode == "" {
		return System{}, ErrInvalidSessionMode
	}
	mode, minutes, err := normalizeSession(mode, minutes)
	if err != nil {
		return System{}, err
	}
	updated, err := s.repo.UpdateSession(ctx, id, mode, minutes)
	if err != nil {
		return System{}, fmt.Errorf("update system session: %w", err)
	}
	return updated, nil
}
