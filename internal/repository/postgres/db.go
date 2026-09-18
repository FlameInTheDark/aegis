// Package postgres implements the relational persistence layer.
// pgx is used directly; Squirrel builds dynamic SQL; all statements are
// parameterized (no string interpolation of user input).
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/FlameInTheDark/aegis/internal/observability"
)

// DB wraps a pgx pool plus Squirrel statement builders.
type DB struct {
	Pool *pgxpool.Pool
	sq   squirrel.StatementBuilderType
}

// Connect opens a pool with conservative defaults.
func Connect(ctx context.Context, url string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse config: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 15 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return &DB{
		Pool: pool,
		sq:   squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar),
	}, nil
}

// Select returns a SELECT builder for postgres.
func (d *DB) Select(columns ...string) squirrel.SelectBuilder { return d.sq.Select(columns...) }

// Insert returns an INSERT builder.
func (d *DB) Insert(into string) squirrel.InsertBuilder { return d.sq.Insert(into) }

// Update returns an UPDATE builder.
func (d *DB) Update(table string) squirrel.UpdateBuilder { return d.sq.Update(table) }

// Delete returns a DELETE builder.
func (d *DB) Delete(from string) squirrel.DeleteBuilder { return d.sq.Delete(from) }

// Query runs a built query.
func (d *DB) Query(ctx context.Context, q squirrel.Sqlizer) (pgx.Rows, error) {
	sql, args, err := q.ToSql()
	if err != nil {
		return nil, fmt.Errorf("postgres: build sql: %w", err)
	}
	return d.Pool.Query(ctx, sql, args...)
}

// QueryRow runs a built query returning one row.
func (d *DB) QueryRow(ctx context.Context, q squirrel.Sqlizer) pgx.Row {
	sql, args, err := q.ToSql()
	if err != nil {
		return errRow{err}
	}
	return d.Pool.QueryRow(ctx, sql, args...)
}

// Exec runs a built statement.
func (d *DB) Exec(ctx context.Context, q squirrel.Sqlizer) (commandTag, error) {
	sql, args, err := q.ToSql()
	if err != nil {
		return commandTag{}, fmt.Errorf("postgres: build sql: %w", err)
	}
	tag, err := d.Pool.Exec(ctx, sql, args...)
	return commandTag{tag}, err
}

// QueryRowSQL runs a raw SQL statement ($N placeholders) returning one row.
// Needed for statements squirrel cannot express (CTEs, jsonb surgery).
func (d *DB) QueryRowSQL(ctx context.Context, sql string, args ...any) pgx.Row {
	return d.Pool.QueryRow(ctx, sql, args...)
}

// ExecSQL runs a raw SQL statement ($N placeholders).
func (d *DB) ExecSQL(ctx context.Context, sql string, args ...any) (commandTag, error) {
	tag, err := d.Pool.Exec(ctx, sql, args...)
	return commandTag{tag}, err
}

type commandTag struct {
	inner interface{ RowsAffected() int64 }
}

func (c commandTag) RowsAffected() int64 { return c.inner.RowsAffected() }

type errRow struct{ err error }

func (r errRow) Scan(dest ...any) error { return r.err }

// WithTx runs fn inside a transaction with explicit commit/rollback.
func (d *DB) WithTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ExecTx executes a built statement on a transaction.
func (d *DB) ExecTx(ctx context.Context, tx pgx.Tx, q squirrel.Sqlizer) error {
	sql, args, err := q.ToSql()
	if err != nil {
		return fmt.Errorf("postgres: build sql: %w", err)
	}
	_, err = tx.Exec(ctx, sql, args...)
	return err
}

// Close drains the pool.
func (d *DB) Close() { d.Pool.Close() }

// CheckHealth implements observability.Checker.
func (d *DB) CheckHealth(ctx context.Context) observability.DependencyHealth {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	start := time.Now()
	if err := d.Pool.Ping(ctx); err != nil {
		return observability.DependencyHealth{Name: "postgres", Status: "down", Detail: err.Error()}
	}
	return observability.DependencyHealth{
		Name: "postgres", Status: "ok", LatencyMs: time.Since(start).Milliseconds(),
	}
}

// nonNil maps nil string slices to empty slices so array-valued columns
// declared NOT NULL DEFAULT '{}' never receive an explicit SQL NULL
// (which would violate the constraint despite the default).
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
