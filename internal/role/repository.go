package role

import "context"

type Repository interface {
	// List returns the roles of a system ordered by name, each with the number of people who have it.
	List(ctx context.Context, systemID string) ([]Role, error)
}
