package migrations

import (
	"io/fs"
	"strconv"
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

func TestPostgresMaxVersion(t *testing.T) {
	// Regression: Postgres() is a sub-FS already rooted at postgres/. The
	// worker used to ReadDir it again with a "postgres" prefix and died at
	// startup with "fatal: schema version: open postgres: file does not
	// exist". PostgresMaxVersion must read the embedded FS and agree with
	// an independent parse of the highest 00NN_*.up.sql file.
	v, err := PostgresMaxVersion()
	if err != nil {
		t.Fatalf("PostgresMaxVersion: %v", err)
	}
	if v <= 0 {
		t.Fatalf("PostgresMaxVersion = %d, want > 0", v)
	}
	files, err := fs.Glob(Postgres(), "[0-9]*.up.sql")
	if err != nil {
		t.Fatalf("glob postgres migrations: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no postgres migrations embedded")
	}
	want := 0
	for _, f := range files {
		n, err := strconv.Atoi(f[:4])
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		if n > want {
			want = n
		}
	}
	if v != want {
		t.Fatalf("PostgresMaxVersion = %d, want %d (highest embedded file)", v, want)
	}
}
