package system

import "context"

type Repository interface {
	// Create stores s and returns it with its generated fields. It returns ErrCodeTaken on a duplicate code.
	Create(ctx context.Context, s System) (System, error)
	List(ctx context.Context) ([]System, error)
	// GetByCode returns ErrSystemNotFound when there is no match.
	GetByCode(ctx context.Context, code string) (System, error)
	// GetByID returns ErrSystemNotFound when there is no match. id must be a valid UUID.
	GetByID(ctx context.Context, id string) (System, error)
	// Delete removes the system and, by cascade, its tenant enablements, accesses and sessions.
	// It returns ErrSystemNotFound when there is no match. id must be a valid UUID.
	Delete(ctx context.Context, id string) error
	// UpdateSession sets the session policy and returns the system. minutes is 0 for a persistent one.
	// It returns ErrSystemNotFound when there is no match. id must be a valid UUID.
	UpdateSession(ctx context.Context, id, mode string, minutes int) (System, error)
}
