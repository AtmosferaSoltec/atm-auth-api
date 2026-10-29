package access

import "context"

type Repository interface {
	// Assign returns ErrUserAlreadyInSystem, ErrUserNotFound, ErrSystemNotEnabled or ErrUnknownRole
	// (the role must exist in the system's catalog).
	Assign(ctx context.Context, a Access) (Access, error)
	// Remove returns ErrAccessNotFound when the user has no access to the system.
	// ListByUser returns every access of a user.
	ListByUser(ctx context.Context, userID string) ([]Detail, error)
	// ListBySystem returns every access to a system, with the user and tenant names.
	ListBySystem(ctx context.Context, systemID string) ([]Detail, error)
	Remove(ctx context.Context, userID, systemID string) error
	// Resolve returns ErrNoAccess unless the user has access and the system, tenant and
	// tenant-system are all active.
	Resolve(ctx context.Context, userID, systemCode string) (Grant, error)
}
