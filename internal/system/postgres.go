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

const columns = "id, code, name, status, session_mode, session_minutes, secret_hash IS NOT NULL, secret_created_at, secret_last_used_at, created_at, updated_at"

func scan(row pgx.Row) (System, error) {
	var s System
	var minutes *int
	err := row.Scan(&s.ID, &s.Code, &s.Name, &s.Status, &s.SessionMode, &minutes, &s.HasSecret, &s.SecretCreatedAt, &s.SecretLastUsedAt, &s.CreatedAt, &s.UpdatedAt)
	if minutes != nil {
		s.SessionMinutes = *minutes
	}
	return s, err
}

func (r *PostgresRepository) Create(ctx context.Context, s System) (System, error) {
	if s.SessionMode == "" {
		s.SessionMode = SessionPersistent
	}
	created, err := scan(r.pool.QueryRow(ctx,
		`INSERT INTO systems (code, name, status, session_mode, session_minutes) VALUES ($1, $2, $3, $4, $5) RETURNING `+columns,
		s.Code, s.Name, s.Status, s.SessionMode, sessionMinutesArg(s.SessionMinutes)))
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

func (r *PostgresRepository) Delete(ctx context.Context, id string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM systems WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete system: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrSystemNotFound
	}
	return nil
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

// sessionMinutesArg stores 0 (a persistent session) as NULL.
func sessionMinutesArg(minutes int) *int {
	if minutes == 0 {
		return nil
	}
	return &minutes
}

func (r *PostgresRepository) UpdateSession(ctx context.Context, id, mode string, minutes int) (System, error) {
	s, err := scan(r.pool.QueryRow(ctx,
		`UPDATE systems SET session_mode = $2, session_minutes = $3, updated_at = now() WHERE id = $1 RETURNING `+columns,
		id, mode, sessionMinutesArg(minutes)))
	if errors.Is(err, pgx.ErrNoRows) {
		return System{}, ErrSystemNotFound
	}
	if err != nil {
		return System{}, fmt.Errorf("update system session: %w", err)
	}
	return s, nil
}
