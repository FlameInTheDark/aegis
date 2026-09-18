package httpx

import (
	"testing"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// Tests for the streamed report-download filename/MIME helpers (the
// Content-Disposition the browser turns into "Save as …").

func TestArtifactContentType(t *testing.T) {
	cases := map[string]string{
		"reports/org/abc.html": "text/html; charset=utf-8",
		"reports/org/abc.pdf":  "application/pdf",
		"reports/org/abc.csv":  "text/csv; charset=utf-8",
		"reports/org/abc.json": "application/json",
		"reports/org/abc":      "text/html; charset=utf-8",
		"no-ext":               "text/html; charset=utf-8",
	}
	for key, want := range cases {
		if got := artifactContentType(key); got != want {
			t.Errorf("artifactContentType(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestArtifactFileName(t *testing.T) {
	created := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	job := &domain.ReportJob{
		ID:          "0198c0de-0000-7000-8000-0123456789ab",
		ArtifactKey: "reports/org/0198c0de-0000-7000-8000-0123456789ab.pdf",
		CreatedAt:   created,
	}
	got := artifactFileName("technical_vulnerability", job)
	want := "aegis-report-technical_vulnerability-20260917-0198c0de.pdf"
	if got != want {
		t.Errorf("artifactFileName = %q, want %q", got, want)
	}
	// Empty definition label falls back to "report"; key without a known
	// extension keeps the html default.
	job2 := &domain.ReportJob{ID: "short", ArtifactKey: "weird", CreatedAt: created}
	if got := artifactFileName("", job2); got != "aegis-report-report-20260917-short.html" {
		t.Errorf("fallback filename = %q", got)
	}
}
