// Command seedtool applies a psql-style seed file (\set vars + :'VAR'
// placeholders) over a pgx connection using the simple protocol, so the
// demo dataset can be loaded without a psql client (sandbox e2e, CI).
package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: seedtool <DATABASE_URL> <seed.sql>")
		os.Exit(2)
	}
	url, path := os.Args[1], os.Args[2]

	src, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}

	// Parse \set VAR 'value' lines; strip them from the script.
	setRe := regexp.MustCompile(`^\\set\s+(\w+)\s+'(.*)'\s*$`)
	varRe := regexp.MustCompile(`:'(\w+)'`)
	vars := map[string]string{}
	var stmts []string
	for _, line := range strings.Split(string(src), "\n") {
		if m := setRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			vars[m[1]] = m[2]
			continue
		}
		stmts = append(stmts, line)
	}
	script := strings.Join(stmts, "\n")
	// :'VAR' is psql's quoted reference — substitute with a quoted literal.
	script = varRe.ReplaceAllStringFunc(script, func(ref string) string {
		name := strings.Trim(ref, ":'")
		if v, ok := vars[name]; ok {
			return "'" + v + "'"
		}
		fmt.Fprintf(os.Stderr, "unknown variable %q\n", name)
		os.Exit(1)
		return ref
	})

	ctx := context.Background()
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse url:", err)
		os.Exit(1)
	}
	// Simple protocol allows multi-statement batches in one Exec.
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, script); err != nil {
		fmt.Fprintln(os.Stderr, "exec seed:", err)
		os.Exit(1)
	}
	fmt.Println("seed applied")
}
