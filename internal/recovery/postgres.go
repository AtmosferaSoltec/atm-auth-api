package recovery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (r *PostgresRepository) Find(ctx context.Context, email string) (Account, bool, error) {
	var a Account
	err := r.pool.QueryRow(ctx,
		`SELECT id, email, full_name FROM users WHERE email = $1 AND status = 'active'`, email).Scan(&a.ID, &a.Email, &a.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, false, nil
	}
	if err != nil {
		return Account{}, false, fmt.Errorf("select account by email: %w", err)
	}
	return a, true, nil
}

func (r *PostgresRepository) CountSince(ctx context.Context, userID string, since time.Time) (int, error) {
	var n int
	if err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM password_reset_codes WHERE user_id = $1 AND created_at >= $2`, userID, since).Scan(&n); err != nil {
		return 0, fmt.Errorf("count reset codes: %w", err)
	}
	return n, nil
}

func (r *PostgresRepository) Replace(ctx context.Context, userID string, hash []byte, expiresAt, now time.Time) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE password_reset_codes SET used_at = $2 WHERE user_id = $1 AND used_at IS NULL`, userID, now); err != nil {
		return fmt.Errorf("void pending codes: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO password_reset_codes (user_id, code_hash, expires_at, created_at) VALUES ($1, $2, $3, $4)`,
		userID, hash, expiresAt, now); err != nil {
		return fmt.Errorf("insert reset code: %w", err)
	}
	return tx.Commit(ctx)
}

func (r *PostgresRepository) Check(ctx context.Context, email string, hash func(string) []byte, now time.Time, newPasswordHash string) (Account, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Account{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var acc Account
	err = tx.QueryRow(ctx,
		`SELECT id, email, full_name FROM users WHERE email = $1 AND status = 'active'`, email).Scan(&acc.ID, &acc.Email, &acc.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrResetCodeWrong
	}
	if err != nil {
		return Account{}, fmt.Errorf("select account: %w", err)
	}

	var (
		codeID   string
		stored   []byte
		expires  time.Time
		attempts int
	)
	err = tx.QueryRow(ctx, `
		SELECT id, code_hash, expires_at, attempts FROM password_reset_codes
		WHERE user_id = $1 AND used_at IS NULL ORDER BY created_at DESC LIMIT 1 FOR UPDATE`, acc.ID).
		Scan(&codeID, &stored, &expires, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrResetCodeWrong
	}
	if err != nil {
		return Account{}, fmt.Errorf("lock reset code: %w", err)
	}
	if !now.Before(expires) || attempts >= MaxCodeAttempts {
		return Account{}, ErrResetCodeWrong
	}
	if !bytes.Equal(hash(acc.ID), stored) {
		// The failed attempt is kept: this transaction commits.
		if _, err := tx.Exec(ctx, `UPDATE password_reset_codes SET attempts = attempts + 1 WHERE id = $1`, codeID); err != nil {
			return Account{}, fmt.Errorf("count attempt: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return Account{}, fmt.Errorf("commit: %w", err)
		}
		return Account{}, ErrResetCodeWrong
	}
	if newPasswordHash != "" {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`UPDATE password_reset_codes SET used_at = $2 WHERE id = $1`, []any{codeID, now}},
			// Reading the code proves control of the mailbox. Changing the password ends any forced change.
			{`UPDATE users SET password_hash = $2, must_change_password = false,
			  email_verified_at = COALESCE(email_verified_at, $3), updated_at = $3 WHERE id = $1`, []any{acc.ID, newPasswordHash, now}},
			{`UPDATE refresh_tokens SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL`, []any{acc.ID, now}},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				return Account{}, fmt.Errorf("apply password reset: %w", err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Account{}, fmt.Errorf("commit: %w", err)
	}
	return acc, nil
}
