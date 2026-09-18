package clickhouse

import (
	"reflect"
	"strings"
	"testing"
)

// A `;` inside a trailing comment must not split the statement — this is the
// exact bug that truncated the security_events DDL (`-- JSON, bounded; large
// payloads go to object storage`) and made ClickHouse reject it with a
// syntax error at the opening paren.
func TestSplitStatementsSemicolonInsideComment(t *testing.T) {
	sql := `CREATE TABLE t
(
    payload String DEFAULT '' CODEC(ZSTD(3)), -- JSON, bounded; large payloads go to object storage
    ts DateTime
) ENGINE = MergeTree ORDER BY ts;`
	got := splitStatements(sql)
	if len(got) != 1 {
		t.Fatalf("expected 1 statement, got %d: %q", len(got), got)
	}
	if !strings.Contains(got[0], "ENGINE = MergeTree") {
		t.Errorf("statement truncated at comment semicolon: %q", got[0])
	}
	if strings.Contains(got[0], "--") {
		t.Errorf("comment must be stripped: %q", got[0])
	}
}

func TestSplitStatementsSemicolonInsideString(t *testing.T) {
	sql := `INSERT INTO t VALUES ('a;b'); SELECT 1;`
	got := splitStatements(sql)
	if len(got) != 2 {
		t.Fatalf("expected 2 statements, got %d: %q", len(got), got)
	}
	if !strings.Contains(got[0], "a;b") {
		t.Errorf("string literal with ';' must survive: %q", got[0])
	}
}

func TestSplitStatementsEscapedQuote(t *testing.T) {
	sql := `INSERT INTO t VALUES ('it''s; fine'); SELECT 2;`
	got := splitStatements(sql)
	if len(got) != 2 {
		t.Fatalf("expected 2 statements, got %d: %q", len(got), got)
	}
	if !strings.Contains(got[0], "it''s; fine") {
		t.Errorf("escaped quote must keep string open: %q", got[0])
	}
}

func TestSplitStatementsFullLineCommentsAndBlanks(t *testing.T) {
	sql := "-- leading comment\n\nCREATE DATABASE IF NOT EXISTS aegis;\n\n-- another comment\nSELECT 1;\n"
	got := splitStatements(sql)
	want := []string{"CREATE DATABASE IF NOT EXISTS aegis", "SELECT 1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSplitStatementsEmpty(t *testing.T) {
	if got := splitStatements(""); got != nil {
		t.Fatalf("empty input must produce nil, got %q", got)
	}
	if got := splitStatements("-- only a comment\n"); got != nil {
		t.Fatalf("comment-only input must produce nil, got %q", got)
	}
}
