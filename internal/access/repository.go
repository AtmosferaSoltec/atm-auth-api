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
	// Remove deletes every access the user has in the system.
	Remove(ctx context.Context, userID, systemID string) error
	// RemoveByID deletes one access, so a person with several companies in a system loses only that one.
	// It returns ErrAccessNotFound.
	RemoveByID(ctx context.Context, id string) error
	// Resolve returns ErrNoAccess unless the user has access and the system, tenant and
	// tenant-system are all active. An empty tenantID picks the access used last, or else the oldest one.
	Resolve(ctx context.Context, userID, systemCode, tenantID string) (Grant, error)
	// Options returns the companies the user can currently work for in the system, ordered by name.
	Options(ctx context.Context, userID, systemCode string) ([]Option, error)
	// MarkUsed records that the user worked for the tenant in the system, so login enters it next time.
	MarkUsed(ctx context.Context, userID, systemID, tenantID string) error
}
