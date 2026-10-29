package credential

import (
	"context"
	"time"
)

type Repository interface {
	// SetSecret stores the hash (replacing any previous one) and returns the system code.
	// It returns ErrSystemNotFound when there is no such system.
	SetSecret(ctx context.Context, systemID, hash string, at time.Time) (code string, err error)
	// ClearSecret removes the secret. It returns ErrSystemNotFound when there is no such system.
	ClearSecret(ctx context.Context, systemID string) error
	// FindByCode returns ErrInvalidClient when there is no system with that code.
	FindByCode(ctx context.Context, code string) (Credential, error)
	// TouchSecret records that the secret was just used.
	TouchSecret(ctx context.Context, systemID string, at time.Time) error
}
