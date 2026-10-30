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

const columns = "id, ruc, legal_name, trade_name, address, department, province, district, ubigeo, phone, email, coalesce(logo_file_id::text, ''), status, created_at, updated_at"

func scan(row pgx.Row) (Tenant, error) {
	var t Tenant
	err := row.Scan(&t.ID, &t.RUC, &t.LegalName, &t.TradeName, &t.Address, &t.Department, &t.Province, &t.District, &t.Ubigeo, &t.Phone, &t.Email, &t.LogoFileID, &t.Status, &t.CreatedAt, &t.UpdatedAt)
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

func (r *PostgresRepository) Update(ctx context.Context, t Tenant) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE tenants SET legal_name = $2, trade_name = $3, address = $4, department = $5, province = $6, district = $7,
		        ubigeo = $8, phone = $9, email = $10, logo_file_id = NULLIF($11, '')::uuid, updated_at = now()
		  WHERE id = $1`,
		t.ID, t.LegalName, t.TradeName, t.Address, t.Department, t.Province, t.District, t.Ubigeo, t.Phone, t.Email, t.LogoFileID)
	if err != nil {
		return fmt.Errorf("update tenant: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrTenantNotFound
	}
	return nil
}

func (r *PostgresRepository) GetByID(ctx context.Context, id string) (Tenant, error) {
	t, err := scan(r.pool.QueryRow(ctx, `SELECT `+columns+` FROM tenants WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Tenant{}, ErrTenantNotFound
	}
	if err != nil {
		return Tenant{}, fmt.Errorf("select tenant: %w", err)
	}
	bySystem, err := r.systemsByTenant(ctx, id)
	if err != nil {
		return Tenant{}, err
	}
	t.Systems = bySystem[id]
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
	rows.Close()
	bySystem, err := r.systemsByTenant(ctx, "")
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Systems = bySystem[out[i].ID]
	}
	return out, nil
}

func (r *PostgresRepository) ListForSystem(ctx context.Context, systemCode string) ([]Tenant, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+columns+` FROM tenants
		  WHERE status = 'active' AND id IN (
		        SELECT ts.tenant_id FROM tenant_systems ts JOIN systems s ON s.id = ts.system_id
		         WHERE s.code = $1 AND s.status = 'active' AND ts.status = 'active')
		  ORDER BY legal_name`, systemCode)
	if err != nil {
		return nil, fmt.Errorf("select tenants of system: %w", err)
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
		return nil, fmt.Errorf("iterate tenants of system: %w", err)
	}
	return out, nil
}

// systemsByTenant returns the enabled systems grouped by tenant id, ordered by system code.
// An empty tenantID returns them for every tenant.
func (r *PostgresRepository) systemsByTenant(ctx context.Context, tenantID string) (map[string][]SystemRef, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT ts.tenant_id, s.id, s.code, s.name
		   FROM tenant_systems ts JOIN systems s ON s.id = ts.system_id
		  WHERE $1 = '' OR ts.tenant_id::text = $1
		  ORDER BY s.code`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("select tenant systems: %w", err)
	}
	defer rows.Close()
	out := map[string][]SystemRef{}
	for rows.Next() {
		var tenant string
		var s SystemRef
		if err := rows.Scan(&tenant, &s.ID, &s.Code, &s.Name); err != nil {
			return nil, fmt.Errorf("scan tenant system: %w", err)
		}
		out[tenant] = append(out[tenant], s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant systems: %w", err)
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

func (r *PostgresRepository) DisableSystem(ctx context.Context, tenantID, systemID string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM tenant_systems WHERE tenant_id = $1 AND system_id = $2`, tenantID, systemID)
	if err != nil {
		return fmt.Errorf("delete tenant system: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrSystemNotEnabled
	}
	return nil
}
