package tenant

import (
	"context"
	"errors"
	"fmt"
	"strings"

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

const columns = "id, ruc, legal_name, trade_name, status, created_at, updated_at"

func scan(row pgx.Row) (Tenant, error) {
	var t Tenant
	err := row.Scan(&t.ID, &t.RUC, &t.LegalName, &t.TradeName, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	return t, err
}

func (r *PostgresRepository) Create(ctx context.Context, t Tenant) (Tenant, error) {
	created, err := scan(r.pool.QueryRow(ctx,
		`INSERT INTO tenants (ruc, legal_name, trade_name, status) VALUES ($1, $2, $3, $4) RETURNING `+columns,
		t.RUC, t.LegalName, t.TradeName, t.Status))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return Tenant{}, ErrRUCTaken
		}
		return Tenant{}, fmt.Errorf("insert tenant: %w", err)
	}
	return created, nil
}

func (r *PostgresRepository) GetByID(ctx context.Context, id string) (Tenant, error) {
	t, err := scan(r.pool.QueryRow(ctx, `SELECT `+columns+` FROM tenants WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Tenant{}, ErrTenantNotFound
	}
	if err != nil {
		return Tenant{}, fmt.Errorf("select tenant: %w", err)
	}
	return t, nil
}

func (r *PostgresRepository) List(ctx context.Context) ([]Tenant, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+columns+` FROM tenants ORDER BY legal_name`)
	if err != nil {
		return nil, fmt.Errorf("select tenants: %w", err)
	}
	defer rows.Close()
	var out []Tenant
	for rows.Next() {
		t, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenants: %w", err)
	}
	return out, nil
}

func (r *PostgresRepository) EnableSystem(ctx context.Context, tenantID, systemID string) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO tenant_systems (tenant_id, system_id) VALUES ($1, $2)`, tenantID, systemID)
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch {
		case pgErr.Code == uniqueViolation:
			return ErrSystemAlreadyEnabled
		case pgErr.Code == foreignKeyViolation && strings.Contains(pgErr.ConstraintName, "tenant_id"):
			return ErrTenantNotFound
		case pgErr.Code == foreignKeyViolation && strings.Contains(pgErr.ConstraintName, "system_id"):
			return ErrSystemNotFound
		}
	}
	return fmt.Errorf("insert tenant system: %w", err)
}
