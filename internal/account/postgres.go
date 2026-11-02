package account

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (r *PostgresRepository) IsPersonal(ctx context.Context, systemCode string) (bool, error) {
	var personal bool
	if err := r.pool.QueryRow(ctx, `SELECT personal FROM systems WHERE code = $1`, systemCode).Scan(&personal); err != nil {
		return false, fmt.Errorf("check system: %w", err)
	}
	return personal, nil
}

func (r *PostgresRepository) Delete(ctx context.Context, userID string) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return nil
}

func (r *PostgresRepository) GoogleLinkedTo(ctx context.Context, subject, userID string) (bool, error) {
	var ok bool
	if err := r.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM external_identities WHERE provider = 'google' AND subject = $1 AND user_id = $2)`,
		subject, userID).Scan(&ok); err != nil {
		return false, fmt.Errorf("check google identity: %w", err)
	}
	return ok, nil
}

func (r *PostgresRepository) ConsumeChallenge(ctx context.Context, hash []byte, now time.Time) (bool, error) {
	tag, err := r.pool.Exec(ctx, `DELETE FROM google_login_challenges WHERE nonce_hash = $1 AND expires_at > $2`, hash, now)
	if err != nil {
		return false, fmt.Errorf("consume google challenge: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
