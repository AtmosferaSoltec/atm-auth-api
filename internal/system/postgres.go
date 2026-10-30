package system

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

const columns = "id, code, name, status, session_mode, requires_ruc, secret_hash IS NOT NULL, secret_created_at, secret_last_used_at, created_at, updated_at"

func scan(row pgx.Row) (System, error) {
	var s System
	err := row.Scan(&s.ID, &s.Code, &s.Name, &s.Status, &s.SessionMode, &s.RequiresRUC, &s.HasSecret, &s.SecretCreatedAt, &s.SecretLastUsedAt, &s.CreatedAt, &s.UpdatedAt)
	return s, err
}

func (r *PostgresRepository) List(ctx context.Context) ([]System, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+columns+` FROM systems ORDER BY code`)
	if err != nil {
		return nil, fmt.Errorf("select systems: %w", err)
	}
	defer rows.Close()
	var out []System
	for rows.Next() {
		s, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("scan system: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate systems: %w", err)
	}
	return out, nil
}

func (r *PostgresRepository) GetByID(ctx context.Context, id string) (System, error) {
	s, err := scan(r.pool.QueryRow(ctx, `SELECT `+columns+` FROM systems WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return System{}, ErrSystemNotFound
	}
	if err != nil {
		return System{}, fmt.Errorf("select system by id: %w", err)
	}
	return s, nil
}

func (r *PostgresRepository) GetByCode(ctx context.Context, code string) (System, error) {
	s, err := scan(r.pool.QueryRow(ctx, `SELECT `+columns+` FROM systems WHERE code = $1`, code))
	if errors.Is(err, pgx.ErrNoRows) {
		return System{}, ErrSystemNotFound
	}
	if err != nil {
		return System{}, fmt.Errorf("select system by code: %w", err)
	}
	return s, nil
}

func (r *PostgresRepository) UpdateSession(ctx context.Context, id, mode string) (System, error) {
	s, err := scan(r.pool.QueryRow(ctx,
		`UPDATE systems SET session_mode = $2, updated_at = now() WHERE id = $1 RETURNING `+columns,
		id, mode))
	if errors.Is(err, pgx.ErrNoRows) {
		return System{}, ErrSystemNotFound
	}
	if err != nil {
		return System{}, fmt.Errorf("update system session: %w", err)
	}
	return s, nil
}
