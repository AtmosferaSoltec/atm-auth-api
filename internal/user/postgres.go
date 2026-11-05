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

// The dni column holds the number of any document type; a missing type is a DNI (older rows).
const columns = "id, CASE WHEN dni IS NOT NULL THEN COALESCE(document_type, 'dni') ELSE '' END, COALESCE(dni, ''), COALESCE(email, ''), email_verified_at IS NOT NULL, full_name, COALESCE(password_hash, ''), status, must_change_password, created_at, updated_at"

func scan(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.DocumentType, &u.DocumentNumber, &u.Email, &u.EmailVerified, &u.FullName, &u.PasswordHash, &u.Status, &u.MustChangePassword, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

func (r *PostgresRepository) Create(ctx context.Context, u User) (User, error) {
	created, err := scan(r.pool.QueryRow(ctx,
		`INSERT INTO users (document_type, dni, email, full_name, password_hash, status, must_change_password, email_verified_at)
		 VALUES (NULLIF($1, ''), NULLIF($2, ''), NULLIF($3, ''), $4, NULLIF($5, ''), $6, $7, CASE WHEN $8 THEN now() END) RETURNING `+columns,
		u.DocumentType, u.DocumentNumber, u.Email, u.FullName, u.PasswordHash, u.Status, u.MustChangePassword, u.EmailVerified))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			if pgErr.ConstraintName == "users_email_key" {
				return User{}, ErrEmailTaken
			}
			return User{}, ErrDocumentTaken
		}
		return User{}, fmt.Errorf("insert user: %w", err)
	}
	return created, nil
}

func (r *PostgresRepository) GetByDocument(ctx context.Context, number string) (User, error) {
	u, err := scan(r.pool.QueryRow(ctx, `SELECT `+columns+` FROM users WHERE dni = $1`, number))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("select user by document: %w", err)
	}
	return u, nil
}

func (r *PostgresRepository) GetByEmail(ctx context.Context, email string) (User, error) {
	u, err := scan(r.pool.QueryRow(ctx, `SELECT `+columns+` FROM users WHERE email = $1`, email))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("select user by email: %w", err)
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
	rows, err := r.pool.Query(ctx, `SELECT `+columns+` FROM users ORDER BY full_name, id LIMIT 500`)
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
