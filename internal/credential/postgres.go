package credential

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

func (r *PostgresRepository) SetSecret(ctx context.Context, systemID, hash string, at time.Time) (string, error) {
	var code string
	err := r.pool.QueryRow(ctx,
		`UPDATE systems SET secret_hash = $2, secret_created_at = $3, secret_last_used_at = NULL, updated_at = now()
		 WHERE id = $1 RETURNING code`, systemID, hash, at).Scan(&code)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrSystemNotFound
	}
	if err != nil {
		return "", fmt.Errorf("set system secret: %w", err)
	}
	return code, nil
}

func (r *PostgresRepository) ClearSecret(ctx context.Context, systemID string) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE systems SET secret_hash = NULL, secret_created_at = NULL, secret_last_used_at = NULL, updated_at = now() WHERE id = $1`, systemID)
	if err != nil {
		return fmt.Errorf("clear system secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrSystemNotFound
	}
	return nil
}

func (r *PostgresRepository) FindByCode(ctx context.Context, code string) (Credential, error) {
	var c Credential
	var hash *string
	var status string
	err := r.pool.QueryRow(ctx, `SELECT id, code, secret_hash, status FROM systems WHERE code = $1`, code).
		Scan(&c.SystemID, &c.Code, &hash, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, ErrInvalidClient
	}
	if err != nil {
		return Credential{}, fmt.Errorf("select system credential: %w", err)
	}
	if hash != nil {
		c.SecretHash = *hash
	}
	c.Active = status == "active"
	return c, nil
}

func (r *PostgresRepository) TouchSecret(ctx context.Context, systemID string, at time.Time) error {
	if _, err := r.pool.Exec(ctx, `UPDATE systems SET secret_last_used_at = $2 WHERE id = $1`, systemID, at); err != nil {
		return fmt.Errorf("touch system secret: %w", err)
	}
	return nil
}
