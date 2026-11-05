package user

import "context"

type Repository interface {
	// Create stores u and returns it with its generated fields. It returns ErrDocumentTaken or ErrEmailTaken on a duplicate.
	Create(ctx context.Context, u User) (User, error)
	// GetByDocument takes a normalized document number (of any type). It returns ErrUserNotFound when there is no match.
	GetByDocument(ctx context.Context, number string) (User, error)
	// GetByEmail takes a normalized email. It returns ErrUserNotFound when there is no match.
	GetByEmail(ctx context.Context, email string) (User, error)
	// GetByID returns ErrUserNotFound when there is no match.
	GetByID(ctx context.Context, id string) (User, error)
	List(ctx context.Context) ([]User, error)
	// SetPassword returns ErrUserNotFound when there is no match.
	SetPassword(ctx context.Context, id, passwordHash string, mustChange bool) error
	// SetStatus returns ErrUserNotFound when there is no match.
	SetStatus(ctx context.Context, id, status string) error
}
