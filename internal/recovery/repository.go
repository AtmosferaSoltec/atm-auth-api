package recovery

import (
	"context"
	"time"
)

// Account is the person a code belongs to.
type Account struct {
	ID    string
	Email string
	Name  string
}

type Repository interface {
	// Find returns the active account with that email, or false.
	Find(ctx context.Context, email string) (Account, bool, error)
	// CountSince counts the codes created for the user since the given time.
	CountSince(ctx context.Context, userID string, since time.Time) (int, error)
	// Replace voids the user's pending codes and stores the new one.
	Replace(ctx context.Context, userID string, hash []byte, expiresAt, now time.Time) error
	// Check looks at the current code of the email in one transaction. hash derives the stored form of a guess
	// from the user id. A wrong guess counts as an attempt. With newPasswordHash set, a right code is consumed, the
	// password changes, the email counts as verified and every session of the user ends, all in the same transaction.
	// Anything wrong is ErrResetCodeWrong, the same for an unknown email, so emails are not revealed.
	Check(ctx context.Context, email string, hash func(userID string) []byte, now time.Time, newPasswordHash string) (Account, error)
}
