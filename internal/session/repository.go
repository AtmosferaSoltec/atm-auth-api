package session

import (
	"context"
	"time"
)

type RefreshStore interface {
	// Create stores t and returns it with its generated ID. An empty FamilyID starts a new family.
	Create(ctx context.Context, t RefreshToken) (RefreshToken, error)
	// FindByHash returns ErrInvalidRefreshToken when there is no match.
	FindByHash(ctx context.Context, hash string) (RefreshToken, error)
	// MarkUsed atomically marks the token as used. It reports false if it was already used or revoked.
	MarkUsed(ctx context.Context, id string, at time.Time) (bool, error)
	RevokeFamily(ctx context.Context, familyID string, at time.Time) error
	// RevokeUser revokes every refresh token of a user.
	RevokeUser(ctx context.Context, userID string, at time.Time) error
}

type AttemptStore interface {
	// Failures counts the failures for key since the given time and returns the oldest one.
	Failures(ctx context.Context, key string, since time.Time) (count int, oldest time.Time, err error)
	// Record stores a failure for key and deletes failures older than cutoff.
	Record(ctx context.Context, key string, at, cutoff time.Time) error
	Clear(ctx context.Context, key string) error
}
