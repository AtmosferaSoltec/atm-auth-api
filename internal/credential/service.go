// Package credential manages the secret each system uses to ask for service tokens.
// One secret per system is enough for every microservice: they only check the token auth-api signs.
package credential

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/AtmosferaSoltec/atm-auth-api/internal/platform"
)

type Service struct {
	repo Repository
	now  func() time.Time
}

func NewService(repo Repository, now func() time.Time) *Service {
	return &Service{repo: repo, now: now}
}

// Generate creates a new secret for the system, replacing the previous one, which stops working at once.
// The returned secret is the only time it is available.
func (s *Service) Generate(ctx context.Context, systemID string) (Issued, error) {
	if !platform.IsUUID(systemID) {
		return Issued{}, ErrInvalidID
	}
	secret, err := newSecret()
	if err != nil {
		return Issued{}, fmt.Errorf("generate system secret: %w", err)
	}
	code, err := s.repo.SetSecret(ctx, systemID, hashSecret(secret), s.now())
	if err != nil {
		return Issued{}, fmt.Errorf("generate system secret: %w", err)
	}
	return Issued{ClientID: code, ClientSecret: secret}, nil
}

// Revoke removes the system's secret. Tokens already issued last until they expire.
func (s *Service) Revoke(ctx context.Context, systemID string) error {
	if !platform.IsUUID(systemID) {
		return ErrInvalidID
	}
	if err := s.repo.ClearSecret(ctx, systemID); err != nil {
		return fmt.Errorf("revoke system secret: %w", err)
	}
	return nil
}

// Verify checks a system code and secret and returns the credential, or ErrInvalidClient.
func (s *Service) Verify(ctx context.Context, clientID, secret string) (Credential, error) {
	c, err := s.repo.FindByCode(ctx, clientID)
	if err != nil && !errors.Is(err, ErrInvalidClient) {
		return Credential{}, fmt.Errorf("verify system secret: %w", err)
	}
	// Always compare, so an unknown system takes as long as a wrong secret.
	match := subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(c.SecretHash)) == 1
	if err != nil || c.SecretHash == "" || !match || !c.Active {
		return Credential{}, ErrInvalidClient
	}
	if err := s.repo.TouchSecret(ctx, c.SystemID, s.now()); err != nil {
		return Credential{}, fmt.Errorf("verify system secret: %w", err)
	}
	return c, nil
}
