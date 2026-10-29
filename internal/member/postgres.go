package member

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

const selectMember = `
	SELECT u.id, u.dni, u.full_name, a.role, a.manage_users, u.status, u.must_change_password
	FROM access a
	JOIN users u ON u.id = a.user_id`

func scan(row pgx.Row) (Member, error) {
	var m Member
	err := row.Scan(&m.UserID, &m.DNI, &m.FullName, &m.Role, &m.ManageUsers, &m.Status, &m.MustChangePassword)
	return m, err
}

func (r *PostgresRepository) List(ctx context.Context, systemID, tenantID string) ([]Member, error) {
	rows, err := r.pool.Query(ctx, selectMember+` WHERE a.system_id = $1 AND a.tenant_id = $2 ORDER BY u.full_name`, systemID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("select members: %w", err)
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		m, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate members: %w", err)
	}
	return out, nil
}

func (r *PostgresRepository) Get(ctx context.Context, systemID, tenantID, userID string) (Member, error) {
	m, err := scan(r.pool.QueryRow(ctx,
		selectMember+` WHERE a.system_id = $1 AND a.tenant_id = $2 AND a.user_id = $3`, systemID, tenantID, userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Member{}, ErrMemberNotFound
	}
	if err != nil {
		return Member{}, fmt.Errorf("select member: %w", err)
	}
	return m, nil
}

func (r *PostgresRepository) UpdateRole(ctx context.Context, systemID, tenantID, userID, role string) (bool, error) {
	tag, err := r.pool.Exec(ctx,
		`UPDATE access SET role = $4 WHERE system_id = $1 AND tenant_id = $2 AND user_id = $3 AND manage_users = false`,
		systemID, tenantID, userID, role)
	if err != nil {
		return false, fmt.Errorf("update member role: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (r *PostgresRepository) Remove(ctx context.Context, systemID, tenantID, userID string) (bool, error) {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM access WHERE system_id = $1 AND tenant_id = $2 AND user_id = $3 AND manage_users = false`,
		systemID, tenantID, userID)
	if err != nil {
		return false, fmt.Errorf("delete member access: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (r *PostgresRepository) OnlyInTenant(ctx context.Context, userID, tenantID string) (bool, error) {
	var other bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM access WHERE user_id = $1 AND tenant_id <> $2)`, userID, tenantID).Scan(&other)
	if err != nil {
		return false, fmt.Errorf("check member tenants: %w", err)
	}
	return !other, nil
}
