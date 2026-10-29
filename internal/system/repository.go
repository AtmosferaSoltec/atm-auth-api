package system

import "context"

type Repository interface {
	// Create stores s and returns it with its generated fields. It returns ErrCodeTaken on a duplicate code.
	Create(ctx context.Context, s System) (System, error)
	List(ctx context.Context) ([]System, error)
	// GetByCode returns ErrSystemNotFound when there is no match.
	GetByCode(ctx context.Context, code string) (System, error)
}
