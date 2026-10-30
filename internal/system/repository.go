package system

import "context"

type Repository interface {
	List(ctx context.Context) ([]System, error)
	// GetByCode returns ErrSystemNotFound when there is no match.
	GetByCode(ctx context.Context, code string) (System, error)
	// GetByID returns ErrSystemNotFound when there is no match. id must be a valid UUID.
	GetByID(ctx context.Context, id string) (System, error)
	// UpdateSession sets the session mode and returns the system.
	// It returns ErrSystemNotFound when there is no match. id must be a valid UUID.
	UpdateSession(ctx context.Context, id, mode string) (System, error)
}
