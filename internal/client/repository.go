package client

import "context"

type Repository interface {
	Create(ctx context.Context, name string) (Client, error)
	// GetByID returns ErrClientNotFound when there is no match.
	GetByID(ctx context.Context, id string) (Client, error)
	// Update renames the client. It returns ErrClientNotFound.
	Update(ctx context.Context, id, name string) error
	// List returns every client with its companies, ordered by name.
	List(ctx context.Context) ([]Client, error)
	// Delete returns ErrClientNotFound, or ErrClientHasTenants while the client still owns companies.
	Delete(ctx context.Context, id string) error
}
