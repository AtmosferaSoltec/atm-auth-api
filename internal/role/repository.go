package role

import "context"

type Repository interface {
	// Create returns ErrSystemNotFound, or ErrRoleExists when the system already has that name
	// (compared without regard to upper or lower case).
	Create(ctx context.Context, r Role) (Role, error)
	// List returns the roles of a system ordered by name, each with the number of people who have it.
	List(ctx context.Context, systemID string) ([]Role, error)
	// UpdateDescription returns ErrRoleNotFound when the system has no such role.
	UpdateDescription(ctx context.Context, systemID, roleID, description string) (Role, error)
	// Delete returns ErrRoleNotFound, or ErrRoleInUse while someone has the role.
	Delete(ctx context.Context, systemID, roleID string) error
}
