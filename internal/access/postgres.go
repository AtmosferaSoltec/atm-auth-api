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
	// A role the catalog retired (inactive) cannot be given, exactly like one that does not exist
	// (that one is refused by the foreign key).
	var retired bool
	if err := r.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM system_roles WHERE system_id = $1 AND name = $2 AND NOT active)`,
		a.SystemID, a.Role).Scan(&retired); err != nil {
		return Access{}, fmt.Errorf("check role: %w", err)
	}
	if retired {
		return Access{}, ErrUnknownRole
	}
	if a.TenantID == "" {
		var personal bool
		if err := r.pool.QueryRow(ctx, `SELECT personal FROM systems WHERE id = $1`, a.SystemID).Scan(&personal); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return Access{}, fmt.Errorf("check system: %w", err)
		} else if !personal {
			return Access{}, ErrTenantRequired
		}
	}
	err := r.pool.QueryRow(ctx,
		`INSERT INTO access (user_id, system_id, tenant_id, role, manage_users) VALUES ($1, $2, NULLIF($3, '')::uuid, $4, $5) RETURNING id, created_at`,
		a.UserID, a.SystemID, a.TenantID, a.Role, a.ManageUsers).Scan(&a.ID, &a.CreatedAt)
	if err == nil {
		return a, nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch {
		case pgErr.Code == uniqueViolation:
			// The same person in the same company of the same system twice.
			return Access{}, ErrUserAlreadyInSystem
		case pgErr.Code == foreignKeyViolation && pgErr.ConstraintName == "access_user_fk":
			return Access{}, ErrUserNotFound
		case pgErr.Code == foreignKeyViolation && pgErr.ConstraintName == "access_tenant_system_fk":
			return Access{}, ErrSystemNotEnabled
		case pgErr.Code == foreignKeyViolation && pgErr.ConstraintName == "access_role_fk":
			return Access{}, ErrUnknownRole
		}
	}
	return Access{}, fmt.Errorf("insert access: %w", err)
}

func (r *PostgresRepository) SelfSignupRole(ctx context.Context, systemCode string) (string, error) {
	var role string
	err := r.pool.QueryRow(ctx,
		`SELECT self_signup_role FROM systems WHERE code = $1 AND status = 'active' AND personal AND self_signup`,
		systemCode).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrSignupClosed
	}
	if err != nil {
		return "", fmt.Errorf("select self signup role: %w", err)
	}
	return role, nil
}

func (r *PostgresRepository) GrantPersonal(ctx context.Context, userID, systemCode, role string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO access (user_id, system_id, tenant_id, role)
		SELECT $1, s.id, NULL, $3 FROM systems s WHERE s.code = $2 AND s.personal
		ON CONFLICT (user_id, system_id) WHERE tenant_id IS NULL DO NOTHING`, userID, systemCode, role)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == foreignKeyViolation && pgErr.ConstraintName == "access_role_fk" {
			return ErrUnknownRole
		}
		return fmt.Errorf("insert personal access: %w", err)
	}
	return nil
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

func (r *PostgresRepository) RemoveByID(ctx context.Context, id string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM access WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete access: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAccessNotFound
	}
	return nil
}

func (r *PostgresRepository) Options(ctx context.Context, userID, systemCode string) ([]Option, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT t.id, COALESCE(t.ruc, ''), COALESCE(NULLIF(t.trade_name, ''), t.legal_name), a.role
		FROM access a
		JOIN systems s         ON s.id = a.system_id
		JOIN tenants t         ON t.id = a.tenant_id
		JOIN tenant_systems ts ON ts.tenant_id = a.tenant_id AND ts.system_id = a.system_id
		WHERE a.user_id = $1 AND s.code = $2
		  AND s.status = 'active' AND t.status = 'active' AND ts.status = 'active'
		ORDER BY COALESCE(NULLIF(t.trade_name, ''), t.legal_name), t.id`, userID, systemCode)
	if err != nil {
		return nil, fmt.Errorf("select access options: %w", err)
	}
	defer rows.Close()
	var out []Option
	for rows.Next() {
		var o Option
		if err := rows.Scan(&o.TenantID, &o.RUC, &o.Name, &o.Role); err != nil {
			return nil, fmt.Errorf("scan access option: %w", err)
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate access options: %w", err)
	}
	return out, nil
}

func (r *PostgresRepository) MarkUsed(ctx context.Context, userID, systemID, tenantID string) error {
	if _, err := r.pool.Exec(ctx,
		`UPDATE access SET last_used_at = now() WHERE user_id = $1 AND system_id = $2 AND tenant_id IS NOT DISTINCT FROM NULLIF($3, '')::uuid`,
		userID, systemID, tenantID); err != nil {
		return fmt.Errorf("mark access used: %w", err)
	}
	return nil
}

func (r *PostgresRepository) Resolve(ctx context.Context, userID, systemCode, tenantID string) (Grant, error) {
	var g Grant
	// A personal access has no tenant: its company columns are empty and nothing about a company must be active.
	err := r.pool.QueryRow(ctx, `
		SELECT a.system_id, s.code, COALESCE(a.tenant_id::text, ''), a.role, a.manage_users, s.session_mode,
		       COALESCE(t.ruc, ''), CASE WHEN u.dni IS NOT NULL THEN COALESCE(u.document_type, 'dni') ELSE '' END,
		       COALESCE(u.dni, ''), COALESCE(u.email, ''), u.full_name,
		       COALESCE(t.client_id::text, ''), COALESCE(c.name, '')
		FROM access a
		JOIN users u    ON u.id = a.user_id
		JOIN systems s  ON s.id = a.system_id
		LEFT JOIN tenants t         ON t.id = a.tenant_id
		LEFT JOIN clients c         ON c.id = t.client_id
		LEFT JOIN tenant_systems ts ON ts.tenant_id = a.tenant_id AND ts.system_id = a.system_id
		WHERE a.user_id = $1 AND s.code = $2
		  AND ($3 = '' OR a.tenant_id::text = $3)
		  AND s.status = 'active'
		  AND (a.tenant_id IS NULL OR (t.status = 'active' AND ts.status = 'active'))
		ORDER BY a.last_used_at DESC NULLS LAST, a.created_at, a.id
		LIMIT 1`,
		userID, systemCode, tenantID).Scan(&g.SystemID, &g.SystemCode, &g.TenantID, &g.Role, &g.ManageUsers, &g.SessionMode, &g.TenantRUC, &g.UserDocumentType, &g.UserDocumentNumber, &g.UserEmail, &g.UserName, &g.ClientID, &g.ClientName)
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
		SELECT a.id, a.user_id, a.system_id, COALESCE(a.tenant_id::text, ''), a.role, a.manage_users, a.created_at,
		       s.code, s.name, COALESCE(NULLIF(t.trade_name, ''), t.legal_name, '')
		FROM access a
		JOIN systems s ON s.id = a.system_id
		LEFT JOIN tenants t ON t.id = a.tenant_id
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
			&d.SystemCode, &d.SystemName, &d.TenantName); err != nil {
			return nil, fmt.Errorf("scan access: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate access: %w", err)
	}
	return out, nil
}

func (r *PostgresRepository) ListBySystem(ctx context.Context, systemID string) ([]Detail, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT a.id, a.user_id, a.system_id, COALESCE(a.tenant_id::text, ''), a.role, a.manage_users, a.created_at,
		       s.code, s.name, COALESCE(NULLIF(t.trade_name, ''), t.legal_name, ''),
		       CASE WHEN u.dni IS NOT NULL THEN COALESCE(u.document_type, 'dni') ELSE '' END, COALESCE(u.dni, ''), COALESCE(u.email, ''), u.full_name
		FROM access a
		JOIN systems s ON s.id = a.system_id
		LEFT JOIN tenants t ON t.id = a.tenant_id
		JOIN users u ON u.id = a.user_id
		WHERE a.system_id = $1
		ORDER BY u.full_name`, systemID)
	if err != nil {
		return nil, fmt.Errorf("select system access: %w", err)
	}
	defer rows.Close()
	var out []Detail
	for rows.Next() {
		var d Detail
		if err := rows.Scan(&d.ID, &d.UserID, &d.SystemID, &d.TenantID, &d.Role, &d.ManageUsers, &d.CreatedAt,
			&d.SystemCode, &d.SystemName, &d.TenantName, &d.UserDocumentType, &d.UserDocumentNumber, &d.UserEmail, &d.UserName); err != nil {
			return nil, fmt.Errorf("scan access: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate access: %w", err)
	}
	return out, nil
}
