package user

import "context"

type Repository interface {
	// Create stores u and returns it with its generated fields. It returns ErrDNITaken on a duplicate DNI.
	Create(ctx context.Context, u User) (User, error)
	// GetByDNI returns ErrUserNotFound when there is no match.
	GetByDNI(ctx context.Context, dni string) (User, error)
	// GetByID returns ErrUserNotFound when there is no match.
	GetByID(ctx context.Context, id string) (User, error)
	List(ctx context.Context) ([]User, error)
	// SetPassword returns ErrUserNotFound when there is no match.
	SetPassword(ctx context.Context, id, passwordHash string, mustChange bool) error
	// SetStatus returns ErrUserNotFound when there is no match.
	SetStatus(ctx context.Context, id, status string) error
}
