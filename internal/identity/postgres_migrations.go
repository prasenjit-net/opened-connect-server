package identity

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	pgxmigrate "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/postgres/*.sql
var postgresMigrations embed.FS

// runPostgresMigrations applies every pending migration in
// migrations/postgres using a short-lived database/sql connection
// (golang-migrate's Postgres driver requires one) that is entirely
// separate from the pgxpool.Pool used for normal store operations.
func runPostgresMigrations(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open migration connection: %w", err)
	}
	defer db.Close()

	source, err := iofs.New(postgresMigrations, "migrations/postgres")
	if err != nil {
		return fmt.Errorf("load embedded migrations: %w", err)
	}
	dbDriver, err := pgxmigrate.WithInstance(db, &pgxmigrate.Config{})
	if err != nil {
		return fmt.Errorf("initialize migration driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", source, "pgx", dbDriver)
	if err != nil {
		return fmt.Errorf("initialize migrator: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}
