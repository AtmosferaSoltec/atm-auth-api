package role

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const foreignKeyViolation = "23503"

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (r *PostgresRepository) Create(ctx context.Context, role Role) (Role, error) {
	// The existence check and the insert are one statement, so two names that differ only in case cannot both get in.
	err := r.pool.QueryRow(ctx,
		`INSERT INTO system_roles (system_id, name, description)
		 SELECT $1::uuid, $2::text, $3::text
		 WHERE NOT EXISTS (SELECT 1 FROM system_roles WHERE system_id = $1::uuid AND lower(name) = lower($2::text))
		 RETURNING id, created_at`,
		role.SystemID, role.Name, role.Description).Scan(&role.ID, &role.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Role{}, ErrRoleExists
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == foreignKeyViolation {
		return Role{}, ErrSystemNotFound
	}
	if err != nil {
		return Role{}, fmt.Errorf("insert system role: %w", err)
	}
	return role, nil
}

func (r *PostgresRepository) List(ctx context.Context, systemID string) ([]Role, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT r.id, r.system_id, r.name, r.description, r.created_at, count(a.id)
		 FROM system_roles r
		 LEFT JOIN access a ON a.system_id = r.system_id AND a.role = r.name
		 WHERE r.system_id = $1
		 GROUP BY r.id
		 ORDER BY r.name`, systemID)
	if err != nil {
		return nil, fmt.Errorf("select system roles: %w", err)
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.ID, &role.SystemID, &role.Name, &role.Description, &role.CreatedAt, &role.Users); err != nil {
			return nil, fmt.Errorf("scan system role: %w", err)
		}
		out = append(out, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate system roles: %w", err)
	}
	return out, nil
}

func (r *PostgresRepository) UpdateDescription(ctx context.Context, systemID, roleID, description string) (Role, error) {
	var role Role
	err := r.pool.QueryRow(ctx,
		`UPDATE system_roles SET description = $3 WHERE system_id = $1 AND id = $2
		 RETURNING id, system_id, name, description, created_at`,
		systemID, roleID, description).Scan(&role.ID, &role.SystemID, &role.Name, &role.Description, &role.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Role{}, ErrRoleNotFound
	}
	if err != nil {
		return Role{}, fmt.Errorf("update system role: %w", err)
	}
	return role, nil
}

func (r *PostgresRepository) Delete(ctx context.Context, systemID, roleID string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM system_roles WHERE system_id = $1 AND id = $2`, systemID, roleID)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == foreignKeyViolation {
		return ErrRoleInUse
	}
	if err != nil {
		return fmt.Errorf("delete system role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrRoleNotFound
	}
	return nil
}
