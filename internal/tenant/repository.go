package tenant

import "context"

type Repository interface {
	// Create returns ErrRUCTaken on a duplicate RUC.
	Create(ctx context.Context, t Tenant) (Tenant, error)
	// GetByID returns ErrTenantNotFound when there is no match.
	GetByID(ctx context.Context, id string) (Tenant, error)
	List(ctx context.Context) ([]Tenant, error)
	// EnableSystem returns ErrTenantNotFound, ErrSystemNotFound or ErrSystemAlreadyEnabled.
	EnableSystem(ctx context.Context, tenantID, systemID string) error
}
