package tenant

import "context"

type Repository interface {
	// Create returns ErrRUCTaken on a duplicate RUC.
	Create(ctx context.Context, t Tenant) (Tenant, error)
	// GetByID returns ErrTenantNotFound when there is no match.
	GetByID(ctx context.Context, id string) (Tenant, error)
	// Update replaces the editable fields (everything but the RUC and the status). It returns ErrTenantNotFound.
	Update(ctx context.Context, t Tenant) error
	List(ctx context.Context) ([]Tenant, error)
	// ListForSystem returns the active tenants that have the system enabled, ordered by legal name. A disabled
	// system, tenant or enablement leaves a tenant out.
	ListForSystem(ctx context.Context, systemCode string) ([]Tenant, error)
	// EnableSystem returns ErrTenantNotFound, ErrSystemNotFound or ErrSystemAlreadyEnabled.
	EnableSystem(ctx context.Context, tenantID, systemID string) error
	// DisableSystem removes the enablement and, by cascade, every access the tenant's users had in that system.
	// It returns ErrSystemNotEnabled when the system was not enabled for the tenant.
	DisableSystem(ctx context.Context, tenantID, systemID string) error
}
