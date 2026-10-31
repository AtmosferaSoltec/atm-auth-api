package catalog

import (
	"context"
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

func (r *PostgresRepository) Upsert(ctx context.Context, systems []System) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	pairs := make([]string, 0)
	for _, s := range systems {
		var id string
		err := tx.QueryRow(ctx,
			`INSERT INTO systems (code, name, requires_ruc) VALUES ($1, $2, $3)
			 ON CONFLICT (code) DO UPDATE SET code = EXCLUDED.code RETURNING id`,
			s.Code, s.Name, s.RequiresRUC).Scan(&id)
		if err != nil {
			return fmt.Errorf("upsert system %s: %w", s.Code, err)
		}
		for _, role := range s.Roles {
			if _, err := tx.Exec(ctx,
				`INSERT INTO system_roles (system_id, name, description) VALUES ($1, $2, $3)
				 ON CONFLICT (system_id, name) DO UPDATE SET description = EXCLUDED.description, active = true`,
				id, role.Name, role.Description); err != nil {
				return fmt.Errorf("upsert role %s/%s: %w", s.Code, role.Name, err)
			}
			pairs = append(pairs, s.Code+"/"+role.Name)
		}
	}
	// A role the catalog no longer declares is retired: it stays (accesses may point at it) but cannot be given again.
	if _, err := tx.Exec(ctx,
		`UPDATE system_roles r SET active = false FROM systems s
		 WHERE s.id = r.system_id AND r.active AND NOT (s.code || '/' || r.name = ANY($1))`, pairs); err != nil {
		return fmt.Errorf("retire roles outside the catalog: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func (r *PostgresRepository) FindOrphans(ctx context.Context, systems []System) (Orphans, error) {
	codes := make([]string, 0, len(systems))
	pairs := make([]string, 0)
	for _, s := range systems {
		codes = append(codes, s.Code)
		for _, role := range s.Roles {
			pairs = append(pairs, s.Code+"/"+role.Name)
		}
	}
	var out Orphans

	rows, err := r.pool.Query(ctx, `SELECT code FROM systems WHERE NOT (code = ANY($1)) ORDER BY code`, codes)
	if err != nil {
		return Orphans{}, fmt.Errorf("select orphan systems: %w", err)
	}
	if out.Systems, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		return Orphans{}, fmt.Errorf("scan orphan systems: %w", err)
	}

	rows, err = r.pool.Query(ctx,
		`SELECT s.code, r.name, count(a.id)
		 FROM system_roles r
		 JOIN systems s ON s.id = r.system_id
		 LEFT JOIN access a ON a.system_id = r.system_id AND a.role = r.name
		 WHERE NOT (s.code || '/' || r.name = ANY($1))
		 GROUP BY s.code, r.name ORDER BY s.code, r.name`, pairs)
	if err != nil {
		return Orphans{}, fmt.Errorf("select orphan roles: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var o OrphanRole
		if err := rows.Scan(&o.SystemCode, &o.Name, &o.Users); err != nil {
			return Orphans{}, fmt.Errorf("scan orphan role: %w", err)
		}
		out.Roles = append(out.Roles, o)
	}
	if err := rows.Err(); err != nil {
		return Orphans{}, fmt.Errorf("iterate orphan roles: %w", err)
	}
	return out, nil
}
