package postgres

import (
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4/database"

	"github.com/golang-migrate/migrate/v4"
	// Registers the "pgx5" database driver in golang-migrate's registry.
	// Without this blank import migrate fails at runtime with
	// "unknown driver pgx5 (forgotten import?)" even though the build succeeds.
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"github.com/FlameInTheDark/aegis/migrations"
)

// Migrator applies schema migrations using golang-migrate. Schema changes
// never happen in arbitrary startup code paths.
type Migrator struct{ m *migrate.Migrate }

// NewMigrator builds a migrator from the embedded migrations.
func NewMigrator(databaseURL string) (*Migrator, error) {
	src, err := iofs.New(migrations.Postgres(), ".")
	if err != nil {
		return nil, fmt.Errorf("migrate: source: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, "pgx5://"+trimScheme(databaseURL))
	if err != nil {
		return nil, fmt.Errorf("migrate: init: %w", err)
	}
	return &Migrator{m: m}, nil
}

func trimScheme(u string) string {
	for _, p := range []string{"postgres://", "postgresql://"} {
		if len(u) > len(p) && u[:len(p)] == p {
			return u[len(p):]
		}
	}
	return u
}

// Up applies all pending migrations.
//
// A previously failed migration leaves its version marked dirty in
// schema_migrations, which would wedge every later start with
// "Dirty database version N". PostgreSQL executes each migration file as a
// single statement batch (one implicit transaction), so a failed migration
// rolled back completely — it is therefore safe to rewind the version
// counter by one, clear the dirty flag and retry from there.
func (m *Migrator) Up() error {
	err := m.m.Up()
	if err == nil || errors.Is(err, migrate.ErrNoChange) {
		return nil
	}
	v, dirty, verr := m.m.Version()
	if verr != nil || !dirty {
		return err
	}
	prev := int(v) - 1
	if prev < 0 {
		prev = database.NilVersion // nothing applied yet
	}
	if ferr := m.m.Force(prev); ferr != nil {
		return fmt.Errorf("migrate: dirty recovery at version %d failed: %w (original error: %v)", v, ferr, err)
	}
	if rerr := m.m.Up(); rerr != nil && !errors.Is(rerr, migrate.ErrNoChange) {
		return rerr
	}
	return nil
}

// Down rolls back one step.
func (m *Migrator) Down() error { return m.m.Steps(-1) }

// Version returns the current schema version.
func (m *Migrator) Version() (uint, bool, error) {
	v, dirty, err := m.m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return 0, false, nil
	}
	return v, dirty, err
}

// Close releases the migrator's database connection.
func (m *Migrator) Close() error {
	srcErr, dbErr := m.m.Close()
	if srcErr != nil {
		return srcErr
	}
	return dbErr
}

// MigrateUp runs migrations against the configured database.
func MigrateUp(databaseURL string) error {
	m, err := NewMigrator(databaseURL)
	if err != nil {
		return err
	}
	return m.Up()
}
