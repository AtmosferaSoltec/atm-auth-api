package role

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (r *PostgresRepository) List(ctx context.Context, systemID string) ([]Role, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT r.id, r.system_id, r.name, r.description, r.active, r.created_at, count(a.id)
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
		if err := rows.Scan(&role.ID, &role.SystemID, &role.Name, &role.Description, &role.Active, &role.CreatedAt, &role.Users); err != nil {
			return nil, fmt.Errorf("scan system role: %w", err)
		}
		out = append(out, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate system roles: %w", err)
	}
	return out, nil
}
