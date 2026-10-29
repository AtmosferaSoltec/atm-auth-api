package user

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

const columns = "id, dni, full_name, password_hash, status, must_change_password, created_at, updated_at"

func scan(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.DNI, &u.FullName, &u.PasswordHash, &u.Status, &u.MustChangePassword, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

func (r *PostgresRepository) Create(ctx context.Context, u User) (User, error) {
	created, err := scan(r.pool.QueryRow(ctx,
		`INSERT INTO users (dni, full_name, password_hash, status, must_change_password) VALUES ($1, $2, $3, $4, $5) RETURNING `+columns,
		u.DNI, u.FullName, u.PasswordHash, u.Status, u.MustChangePassword))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return User{}, ErrDNITaken
		}
		return User{}, fmt.Errorf("insert user: %w", err)
	}
	return created, nil
}

func (r *PostgresRepository) GetByDNI(ctx context.Context, dni string) (User, error) {
	u, err := scan(r.pool.QueryRow(ctx, `SELECT `+columns+` FROM users WHERE dni = $1`, dni))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("select user by dni: %w", err)
	}
	return u, nil
}

func (r *PostgresRepository) GetByID(ctx context.Context, id string) (User, error) {
	u, err := scan(r.pool.QueryRow(ctx, `SELECT `+columns+` FROM users WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("select user by id: %w", err)
	}
	return u, nil
}

func (r *PostgresRepository) List(ctx context.Context) ([]User, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+columns+` FROM users ORDER BY dni LIMIT 500`)
	if err != nil {
		return nil, fmt.Errorf("select users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}
	return out, nil
}

func (r *PostgresRepository) SetPassword(ctx context.Context, id, passwordHash string, mustChange bool) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE users SET password_hash = $2, must_change_password = $3, updated_at = now() WHERE id = $1`,
		id, passwordHash, mustChange)
	if err != nil {
		return fmt.Errorf("update user password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (r *PostgresRepository) SetStatus(ctx context.Context, id, status string) error {
	tag, err := r.pool.Exec(ctx, `UPDATE users SET status = $2, updated_at = now() WHERE id = $1`, id, status)
	if err != nil {
		return fmt.Errorf("update user status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}
