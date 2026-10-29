package system

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const uniqueViolation = "23505"

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

const columns = "id, code, name, status, created_at, updated_at"

func scan(row pgx.Row) (System, error) {
	var s System
	err := row.Scan(&s.ID, &s.Code, &s.Name, &s.Status, &s.CreatedAt, &s.UpdatedAt)
	return s, err
}

func (r *PostgresRepository) Create(ctx context.Context, s System) (System, error) {
	created, err := scan(r.pool.QueryRow(ctx,
		`INSERT INTO systems (code, name, status) VALUES ($1, $2, $3) RETURNING `+columns,
		s.Code, s.Name, s.Status))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return System{}, ErrCodeTaken
		}
		return System{}, fmt.Errorf("insert system: %w", err)
	}
	return created, nil
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
