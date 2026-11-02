package google

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore { return &PostgresStore{pool: pool} }

func (s *PostgresStore) UserBySubject(ctx context.Context, subject string) (string, bool, error) {
	var id string
	err := s.pool.QueryRow(ctx,
		`SELECT user_id FROM external_identities WHERE provider = 'google' AND subject = $1`, subject).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("select google identity: %w", err)
	}
	return id, true, nil
}

func (s *PostgresStore) Link(ctx context.Context, subject, userID string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO external_identities (provider, subject, user_id) VALUES ('google', $1, $2)`, subject, userID)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrIdentityConflict
	}
	if err != nil {
		return fmt.Errorf("link google identity: %w", err)
	}
	// Google vouches for the mailbox.
	if _, err := s.pool.Exec(ctx,
		`UPDATE users SET email_verified_at = COALESCE(email_verified_at, now()) WHERE id = $1 AND email IS NOT NULL`, userID); err != nil {
		return fmt.Errorf("mark email verified: %w", err)
	}
	return nil
}

func (s *PostgresStore) CreateChallenge(ctx context.Context, hash []byte, expiresAt, now time.Time) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM google_login_challenges WHERE expires_at < $1`, now); err != nil {
		return fmt.Errorf("purge google challenges: %w", err)
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO google_login_challenges (nonce_hash, expires_at) VALUES ($1, $2)`, hash, expiresAt); err != nil {
		return fmt.Errorf("insert google challenge: %w", err)
	}
	return nil
}

// ConsumeChallenge deletes the challenge and reports whether it existed and was still valid.
func (s *PostgresStore) ConsumeChallenge(ctx context.Context, hash []byte, now time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM google_login_challenges WHERE nonce_hash = $1 AND expires_at > $2`, hash, now)
	if err != nil {
		return false, fmt.Errorf("consume google challenge: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
