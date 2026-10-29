package member

import "context"

// Repository only reads and changes rows inside one (system, tenant) scope.
type Repository interface {
	List(ctx context.Context, systemID, tenantID string) ([]Member, error)
	// Get returns ErrMemberNotFound when the user is not a member of that tenant in that system.
	Get(ctx context.Context, systemID, tenantID, userID string) (Member, error)
	// UpdateRole and Remove never touch members with manage_users. They report whether a row changed.
	UpdateRole(ctx context.Context, systemID, tenantID, userID, role string) (bool, error)
	Remove(ctx context.Context, systemID, tenantID, userID string) (bool, error)
	// OnlyInTenant reports whether every access of the user belongs to tenantID.
	OnlyInTenant(ctx context.Context, userID, tenantID string) (bool, error)
}
