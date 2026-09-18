package feeds

// DB-backed integration test for the cvelistv5 sync pipeline (bootstrap =
// midnight snapshot + daily delta; same-day = delta only; discovery failure =
// static fallback chain). Runs against a real PostgreSQL; skipped unless
// AEGIS_TEST_PG_URL is set, e.g.
//
//      AEGIS_TEST_PG_URL=postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable \
//        go test ./internal/feeds/ -run IntegrationCVELIST

import (
	"archive/zip"
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testURL gates on the same variable as the postgres repo integration tests.
func testURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("AEGIS_TEST_PG_URL")
	if u == "" {
		t.Skip("AEGIS_TEST_PG_URL not set; skipping integration test")
	}
	return u
}

// makeCVE5JSON renders a minimal PUBLISHED CVE JSON 5.0 record.
func makeCVE5JSON(id string) string {
	return `{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"` + id + `","state":"PUBLISHED","datePublished":"2026-09-16T10:00:00.000Z","dateUpdated":"2026-09-16T12:00:00.000Z"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"Test record ` + id + `"}],"affected":[{"vendor":"acme","product":"widget","cpes":["cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"]}]}}}`
}

// makeCVELISTZip builds an in-memory zip with the given (path, content) files.
func makeCVELISTZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// cvelistStubGitHub mimics the GitHub release pages + release-asset downloads.
func cvelistStubGitHub(t *testing.T, fullZip, deltaZip []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/releases/tag/cve_2026-09-16_1800Z", http.StatusFound)
	})
	mux.HandleFunc("/releases/tag/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html></html>"))
	})
	mux.HandleFunc("/releases/expanded_assets/cve_2026-09-16_1800Z", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<a href="/releases/download/cve_2026-09-16_1800Z/2026-09-16_all_CVEs_at_midnight.zip.zip">full</a>` +
			`<a href="/releases/download/cve_2026-09-16_1800Z/2026-09-16_delta_CVEs_at_1800Z.zip">delta</a>`))
	})
	mux.HandleFunc("/releases/download/cve_2026-09-16_1800Z/2026-09-16_all_CVEs_at_midnight.zip.zip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fullZip)
	})
	mux.HandleFunc("/releases/download/cve_2026-09-16_1800Z/2026-09-16_delta_CVEs_at_1800Z.zip", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(deltaZip)
	})
	return httptest.NewServer(mux)
}

func cvelistCountCVEs(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM vulnerabilities").Scan(&n); err != nil {
		t.Fatalf("count vulnerabilities: %v", err)
	}
	return n
}

// stubWithoutDelta mimics a release whose latest tag carries no delta asset
// yet (fresh UTC day before the first delta publish).
func stubWithoutDelta(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/releases/tag/cve_2026-09-17_0000Z", http.StatusFound)
	})
	mux.HandleFunc("/releases/tag/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html></html>"))
	})
	mux.HandleFunc("/releases/expanded_assets/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<a href="/releases/download/cve_2026-09-17_0000Z/2026-09-17_all_CVEs_at_midnight.zip.zip">full</a>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestIntegrationCVELISTSync(t *testing.T) {
	url := testURL(t)
	if err := pg.MigrateUp(url); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	db, err := pg.Connect(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "TRUNCATE vulnerabilities, vulnerability_cpe_matches"); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	fullZip := makeCVELISTZip(t, map[string]string{
		"cves/2026/9xxx/CVE-2026-11111.json": makeCVE5JSON("CVE-2026-11111"),
		"cves/2026/9xxx/CVE-2026-22222.json": makeCVE5JSON("CVE-2026-22222"),
		"README.md":                          "not a record",
	})
	deltaZip := makeCVELISTZip(t, map[string]string{
		"deltaCves/CVE-2026-33333.json": makeCVE5JSON("CVE-2026-33333"),
	})
	srv := cvelistStubGitHub(t, fullZip, deltaZip)
	defer srv.Close()

	var last atomic.Value // time.Time
	job := &CVEListV5Job{
		Client:  NewClient(slog.Default()),
		Vulns:   pg.NewVulnRepo(db),
		Log:     slog.Default(),
		BaseURL: srv.URL,
		TmpDir:  t.TempDir(),
		LastSyncFn: func(context.Context) time.Time {
			if v, ok := last.Load().(time.Time); ok {
				return v
			}
			return time.Time{}
		},
	}

	// 1. Bootstrap (never synced): midnight snapshot + delta, both ingested.
	p, c, u, r, err := job.Sync(ctx, false)
	if err != nil {
		t.Fatalf("bootstrap sync: %v", err)
	}
	if p != 3 || c != 3 || u != 0 || r != 0 {
		t.Errorf("bootstrap counts = (%d,%d,%d,%d), want (3,3,0,0)", p, c, u, r)
	}
	if n := cvelistCountCVEs(t, pool); n != 3 {
		t.Errorf("bootstrap rows = %d, want 3", n)
	}

	// CPE matches must have landed with the records (matching engine input).
	var cpes int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM vulnerability_cpe_matches").Scan(&cpes); err != nil {
		t.Fatal(err)
	}
	if cpes != 3 {
		t.Errorf("cpe matches = %d, want 3", cpes)
	}

	// 2. Same-day incremental: delta only — full snapshot must NOT be pulled.
	now := time.Date(2026, 9, 16, 18, 53, 0, 0, time.UTC)
	last.Store(now)
	p, c, _, _, err = job.Sync(ctx, false)
	if err != nil {
		t.Fatalf("same-day sync: %v", err)
	}
	if p != 1 || c != 1 {
		t.Errorf("same-day counts = (%d,%d), want (1,1) delta-only", p, c)
	}
	if n := cvelistCountCVEs(t, pool); n != 3 {
		t.Errorf("same-day rows = %d, want 3 (upsert idempotent)", n)
	}

	// 3. Same-day with no delta published yet: honest skip, no error.
	job2 := *job
	job2.BaseURL = stubWithoutDelta(t)
	last.Store(now)
	p, _, _, _, err = job2.Sync(ctx, false)
	if err != nil {
		t.Fatalf("no-delta same-day sync: %v", err)
	}
	if p != 0 {
		t.Errorf("no-delta same-day processed = %d, want 0 (skipped)", p)
	}

	// 4. Discovery failure falls back to the static chain: a branch-archive
	// shaped zip (cvelistV5-main/ prefix) must ingest via cves/ matching.
	branchZip := makeCVELISTZip(t, map[string]string{
		"cvelistV5-main/cves/2026/9xxx/CVE-2026-44444.json": makeCVE5JSON("CVE-2026-44444"),
	})
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Everything 404s except the fallback artifact URL.
		if strings.HasSuffix(r.URL.Path, "/archive/refs/heads/main.zip") {
			_, _ = w.Write(branchZip)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv2.Close()
	job3 := *job
	job3.BaseURL = "http://127.0.0.1:1" // discovery unreachable
	job3.FallbackURLs = []cvelistDownload{{URL: srv2.URL + "/archive/refs/heads/main.zip", MaxBytes: 64 << 20}}
	last.Store(time.Time{}) // not synced recently → fallback allowed
	p, _, _, _, err = job3.Sync(ctx, false)
	if err != nil {
		t.Fatalf("fallback sync: %v", err)
	}
	if p != 1 {
		t.Errorf("fallback processed = %d, want 1", p)
	}
	if n := cvelistCountCVEs(t, pool); n != 4 {
		t.Errorf("rows after fallback = %d, want 4", n)
	}

	// 5. Synced today + discovery failure: no multi-GB re-bootstrap, skip.
	last.Store(now)
	p, _, _, _, err = job3.Sync(ctx, false)
	if err != nil {
		t.Fatalf("fallback same-day sync: %v", err)
	}
	if p != 0 {
		t.Errorf("fallback same-day processed = %d, want 0 (skipped)", p)
	}
}
