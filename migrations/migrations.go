// Package migrations embeds the SQL migration files so binaries can apply
// them without external files (golang-migrate source driver: iofs).
package migrations

import (
	"embed"
	"io/fs"
)

//go:embed postgres/*.sql
var postgresFS embed.FS

//go:embed clickhouse/*.sql
var clickhouseFS embed.FS

// Postgres returns the embedded PostgreSQL migrations.
func Postgres() fs.FS {
	sub, err := fs.Sub(postgresFS, "postgres")
	if err != nil {
		panic(err)
	}
	return sub
}

// ClickHouse returns the embedded ClickHouse schema files.
func ClickHouse() fs.FS {
	sub, err := fs.Sub(clickhouseFS, "clickhouse")
	if err != nil {
		panic(err)
	}
	return sub
}
