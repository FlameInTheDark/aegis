// Package migrations embeds the SQL migration files so binaries can apply
// them without external files (golang-migrate source driver: iofs).
package migrations

import (
	"embed"
	"io/fs"
	"strings"
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

// PostgresMaxVersion returns the highest embedded postgres migration version
// (the number the applied schema must reach before consumers may run).
// Regression note: Postgres() is a sub-FS already rooted at postgres/ — the
// worker used to ReadDir it again with a "postgres" prefix and died at
// startup with "open postgres: file does not exist".
func PostgresMaxVersion() (int, error) {
	entries, err := fs.ReadDir(postgresFS, "postgres")
	if err != nil {
		return 0, err
	}
	max := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		n := 0
		for _, r := range name {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
		}
		if n > max {
			max = n
		}
	}
	return max, nil
}
