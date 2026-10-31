package catalog

import "context"

type Repository interface {
	// Upsert registers the systems and roles in one transaction. A system that already exists keeps its name, secret and
	// session policy; a role that already exists gets the description of the catalog and is active. Roles in the database that
	// the catalog does not declare are marked inactive. Nothing is ever deleted.
	Upsert(ctx context.Context, systems []System) error
	// FindOrphans returns the systems and roles in the database that are not in the given catalog.
	FindOrphans(ctx context.Context, systems []System) (Orphans, error)
}
