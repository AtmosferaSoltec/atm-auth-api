package client

import (
	"context"
	"fmt"
	"unicode/utf8"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

type Service struct {
	repo Repository
}

func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

func validName(raw string) (string, error) {
	name := normalizeName(raw)
	if name == "" {
		return "", ErrInvalidName
	}
	if utf8.RuneCountInString(name) > maxName {
		return "", ErrNameTooLong
	}
	return name, nil
}

func (s *Service) Create(ctx context.Context, name string) (Client, error) {
	name, err := validName(name)
	if err != nil {
		return Client{}, err
	}
	created, err := s.repo.Create(ctx, name)
	if err != nil {
		return Client{}, fmt.Errorf("create client: %w", err)
	}
	return created, nil
}

func (s *Service) Get(ctx context.Context, id string) (Client, error) {
	if !platform.IsUUID(id) {
		return Client{}, ErrInvalidID
	}
	c, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return Client{}, fmt.Errorf("get client: %w", err)
	}
	return c, nil
}

func (s *Service) Rename(ctx context.Context, id, name string) (Client, error) {
	if !platform.IsUUID(id) {
		return Client{}, ErrInvalidID
	}
	name, err := validName(name)
	if err != nil {
		return Client{}, err
	}
	if err := s.repo.Update(ctx, id, name); err != nil {
		return Client{}, fmt.Errorf("rename client: %w", err)
	}
	return s.Get(ctx, id)
}

func (s *Service) List(ctx context.Context) ([]Client, error) {
	cs, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	return cs, nil
}

// Delete removes a client that owns no companies. Move or remove its companies first.
func (s *Service) Delete(ctx context.Context, id string) error {
	if !platform.IsUUID(id) {
		return ErrInvalidID
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete client: %w", err)
	}
	return nil
}
