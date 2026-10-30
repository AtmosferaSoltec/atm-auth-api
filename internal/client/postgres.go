package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	foreignKeyViolation = "23503"
	// restrictViolation is what ON DELETE RESTRICT raises (NO ACTION raises the foreign key one).
	restrictViolation = "23001"
)

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

const columns = "id, name, created_at, updated_at"

func scan(row pgx.Row) (Client, error) {
	var c Client
	err := row.Scan(&c.ID, &c.Name, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

func (r *PostgresRepository) Create(ctx context.Context, name string) (Client, error) {
	c, err := scan(r.pool.QueryRow(ctx, `INSERT INTO clients (name) VALUES ($1) RETURNING `+columns, name))
	if err != nil {
		return Client{}, fmt.Errorf("insert client: %w", err)
	}
	return c, nil
}

func (r *PostgresRepository) GetByID(ctx context.Context, id string) (Client, error) {
	c, err := scan(r.pool.QueryRow(ctx, `SELECT `+columns+` FROM clients WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Client{}, ErrClientNotFound
	}
	if err != nil {
		return Client{}, fmt.Errorf("select client: %w", err)
	}
	byClient, err := r.tenantsByClient(ctx, id)
	if err != nil {
		return Client{}, err
	}
	c.Tenants = byClient[id]
	return c, nil
}

func (r *PostgresRepository) Update(ctx context.Context, id, name string) error {
	tag, err := r.pool.Exec(ctx, `UPDATE clients SET name = $2, updated_at = now() WHERE id = $1`, id, name)
	if err != nil {
		return fmt.Errorf("update client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrClientNotFound
	}
	return nil
}

func (r *PostgresRepository) List(ctx context.Context) ([]Client, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+columns+` FROM clients ORDER BY lower(name), id`)
	if err != nil {
		return nil, fmt.Errorf("select clients: %w", err)
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		c, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("scan client: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate clients: %w", err)
	}
	rows.Close()
	byClient, err := r.tenantsByClient(ctx, "")
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Tenants = byClient[out[i].ID]
	}
	return out, nil
}

func (r *PostgresRepository) Delete(ctx context.Context, id string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM clients WHERE id = $1`, id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (pgErr.Code == restrictViolation || pgErr.Code == foreignKeyViolation) {
			return ErrClientHasTenants
		}
		return fmt.Errorf("delete client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrClientNotFound
	}
	return nil
}

// tenantsByClient returns the companies grouped by client id, ordered by name. An empty clientID returns them all.
func (r *PostgresRepository) tenantsByClient(ctx context.Context, clientID string) (map[string][]TenantRef, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT client_id, id, coalesce(ruc, ''), coalesce(nullif(btrim(trade_name), ''), legal_name)
		   FROM tenants
		  WHERE $1 = '' OR client_id::text = $1
		  ORDER BY lower(coalesce(nullif(btrim(trade_name), ''), legal_name)), id`, clientID)
	if err != nil {
		return nil, fmt.Errorf("select client tenants: %w", err)
	}
	defer rows.Close()
	out := map[string][]TenantRef{}
	for rows.Next() {
		var client string
		var t TenantRef
		if err := rows.Scan(&client, &t.ID, &t.RUC, &t.DisplayName); err != nil {
			return nil, fmt.Errorf("scan client tenant: %w", err)
		}
		out[client] = append(out[client], t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate client tenants: %w", err)
	}
	return out, nil
}
