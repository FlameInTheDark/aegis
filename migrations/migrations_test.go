package migrations

import (
	"io/fs"
	"testing"
)

func TestPostgresMigrationsEmbedded(t *testing.T) {
	files, err := fs.Glob(Postgres(), "*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no postgres migrations embedded")
	}
	for _, f := range files {
		if _, err := fs.Stat(Postgres(), f); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
}

func TestClickHouseSchemaEmbedded(t *testing.T) {
	// Regression: ClickHouse() is a sub-FS already rooted at clickhouse/,
	// so files must open WITHOUT the clickhouse/ prefix. Callers previously
	// opened "clickhouse/001_schema.sql" and failed at runtime with
	// "open clickhouse/001_schema.sql: file does not exist".
	f, err := ClickHouse().Open("001_schema.sql")
	if err != nil {
		t.Fatalf("open 001_schema.sql: %v", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() == 0 {
		t.Fatal("clickhouse schema is empty")
	}
}
