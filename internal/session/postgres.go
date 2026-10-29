package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (r *PostgresRepository) Create(ctx context.Context, t RefreshToken) (RefreshToken, error) {
	err := r.pool.QueryRow(ctx, `
		INSERT INTO refresh_tokens (family_id, token_hash, role, user_id, system_id, expires_at)
		VALUES (COALESCE(NULLIF($1, '')::uuid, gen_random_uuid()), $2, $3, NULLIF($4, '')::uuid, NULLIF($5, '')::uuid, $6)
		RETURNING id, family_id`,
		t.FamilyID, t.TokenHash, t.Role, t.UserID, t.SystemID, t.ExpiresAt,
	).Scan(&t.ID, &t.FamilyID)
	if err != nil {
		return RefreshToken{}, fmt.Errorf("insert refresh token: %w", err)
	}
	return t, nil
}

func (r *PostgresRepository) FindByHash(ctx context.Context, hash string) (RefreshToken, error) {
	var t RefreshToken
	err := r.pool.QueryRow(ctx, `
		SELECT rt.id, rt.family_id, rt.token_hash, rt.role,
		       COALESCE(rt.user_id::text, ''), COALESCE(rt.system_id::text, ''), COALESCE(s.code, ''),
		       rt.expires_at, rt.used_at, rt.revoked_at
		FROM refresh_tokens rt
		LEFT JOIN systems s ON s.id = rt.system_id
		WHERE rt.token_hash = $1`, hash,
	).Scan(&t.ID, &t.FamilyID, &t.TokenHash, &t.Role, &t.UserID, &t.SystemID, &t.SystemCode,
		&t.ExpiresAt, &t.UsedAt, &t.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return RefreshToken{}, ErrInvalidRefreshToken
	}
	if err != nil {
		return RefreshToken{}, fmt.Errorf("select refresh token: %w", err)
	}
	return t, nil
}

func (r *PostgresRepository) MarkUsed(ctx context.Context, id string, at time.Time) (bool, error) {
	tag, err := r.pool.Exec(ctx,
		`UPDATE refresh_tokens SET used_at = $2 WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL`, id, at)
	if err != nil {
		return false, fmt.Errorf("mark refresh token used: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (r *PostgresRepository) RevokeFamily(ctx context.Context, familyID string, at time.Time) error {
	if _, err := r.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = $2 WHERE family_id = $1 AND revoked_at IS NULL`, familyID, at); err != nil {
		return fmt.Errorf("revoke refresh token family: %w", err)
	}
	return nil
}

func (r *PostgresRepository) RevokeUser(ctx context.Context, userID string, at time.Time) error {
	if _, err := r.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL`, userID, at); err != nil {
		return fmt.Errorf("revoke user refresh tokens: %w", err)
	}
	return nil
}

func (r *PostgresRepository) Failures(ctx context.Context, key string, since time.Time) (int, time.Time, error) {
	var count int
	var oldest *time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT count(*), min(attempted_at) FROM login_attempts WHERE key = $1 AND attempted_at > $2`, key, since,
	).Scan(&count, &oldest)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("count login failures: %w", err)
	}
	if oldest == nil {
		return count, time.Time{}, nil
	}
	return count, *oldest, nil
}

func (r *PostgresRepository) Record(ctx context.Context, key string, at, cutoff time.Time) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM login_attempts WHERE attempted_at < $1`, cutoff); err != nil {
		return fmt.Errorf("prune login attempts: %w", err)
	}
	if _, err := r.pool.Exec(ctx, `INSERT INTO login_attempts (key, attempted_at) VALUES ($1, $2)`, key, at); err != nil {
		return fmt.Errorf("insert login attempt: %w", err)
	}
	return nil
}

func (r *PostgresRepository) Clear(ctx context.Context, key string) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM login_attempts WHERE key = $1`, key); err != nil {
		return fmt.Errorf("clear login attempts: %w", err)
	}
	return nil
}
