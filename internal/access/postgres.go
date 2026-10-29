package access

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	uniqueViolation     = "23505"
	foreignKeyViolation = "23503"
)

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (r *PostgresRepository) Assign(ctx context.Context, a Access) (Access, error) {
	err := r.pool.QueryRow(ctx,
		`INSERT INTO access (user_id, system_id, tenant_id, role, manage_users) VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at`,
		a.UserID, a.SystemID, a.TenantID, a.Role, a.ManageUsers).Scan(&a.ID, &a.CreatedAt)
	if err == nil {
		return a, nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch {
		case pgErr.Code == uniqueViolation:
			return Access{}, ErrUserAlreadyInSystem
		case pgErr.Code == foreignKeyViolation && pgErr.ConstraintName == "access_user_fk":
			return Access{}, ErrUserNotFound
		case pgErr.Code == foreignKeyViolation && pgErr.ConstraintName == "access_tenant_system_fk":
			return Access{}, ErrSystemNotEnabled
		}
	}
	return Access{}, fmt.Errorf("insert access: %w", err)
}

func (r *PostgresRepository) Remove(ctx context.Context, userID, systemID string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM access WHERE user_id = $1 AND system_id = $2`, userID, systemID)
	if err != nil {
		return fmt.Errorf("delete access: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAccessNotFound
	}
	return nil
}

func (r *PostgresRepository) Resolve(ctx context.Context, userID, systemCode string) (Grant, error) {
	var g Grant
	err := r.pool.QueryRow(ctx, `
		SELECT a.system_id, s.code, a.tenant_id, a.role, a.manage_users
		FROM access a
		JOIN systems s        ON s.id = a.system_id
		JOIN tenants t        ON t.id = a.tenant_id
		JOIN tenant_systems ts ON ts.tenant_id = a.tenant_id AND ts.system_id = a.system_id
		WHERE a.user_id = $1 AND s.code = $2
		  AND s.status = 'active' AND t.status = 'active' AND ts.status = 'active'`,
		userID, systemCode).Scan(&g.SystemID, &g.SystemCode, &g.TenantID, &g.Role, &g.ManageUsers)
	if errors.Is(err, pgx.ErrNoRows) {
		return Grant{}, ErrNoAccess
	}
	if err != nil {
		return Grant{}, fmt.Errorf("select access: %w", err)
	}
	return g, nil
}

func (r *PostgresRepository) ListByUser(ctx context.Context, userID string) ([]Detail, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT a.id, a.user_id, a.system_id, a.tenant_id, a.role, a.manage_users, a.created_at,
		       s.code, COALESCE(NULLIF(t.trade_name, ''), t.legal_name)
		FROM access a
		JOIN systems s ON s.id = a.system_id
		JOIN tenants t ON t.id = a.tenant_id
		WHERE a.user_id = $1
		ORDER BY s.code`, userID)
	if err != nil {
		return nil, fmt.Errorf("select user access: %w", err)
	}
	defer rows.Close()
	var out []Detail
	for rows.Next() {
		var d Detail
		if err := rows.Scan(&d.ID, &d.UserID, &d.SystemID, &d.TenantID, &d.Role, &d.ManageUsers, &d.CreatedAt,
			&d.SystemCode, &d.TenantName); err != nil {
			return nil, fmt.Errorf("scan access: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate access: %w", err)
	}
	return out, nil
}
