package system

import (
	"context"
	"fmt"
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
}

func (s *Service) Create(ctx context.Context, in CreateInput) (System, error) {
	if !validCode(in.Code) {
		return System{}, ErrInvalidCode
	}
	name := normalizeName(in.Name)
	if name == "" {
		return System{}, ErrInvalidName
	}
	created, err := s.repo.Create(ctx, System{Code: in.Code, Name: name, Status: StatusActive})
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
