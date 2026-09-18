package reports

import (
	"bytes"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// renderPDF must produce a structurally valid PDF: correct header, every
// xref offset landing exactly on its "N 0 obj", and %%EOF at the end.
func TestRenderPDFStructure(t *testing.T) {
	d := &reportData{
		Title: "Executive Security Report", Type: "executive_security", OrgID: "org-1",
		GeneratedAt: time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC),
		Summary:     map[string]any{"total_findings": 3, "kev": 1, "assets": 2, "by_severity": map[string]int{"critical": 1, "high": 2}},
		Recommendations: []string{
			"Remediate 1 critical finding(s) first; 1 are listed as known exploited.",
			"A recommendation long enough to exercise the line wrapping path in the fixed-pitch writer, repeated text to force at least one extra line so wrapping is genuinely covered by this test case.",
		},
		Findings: []domain.Finding{
			{RiskScore: 87, Severity: domain.SeverityCritical, CVEID: "CVE-2024-1234", Status: domain.FindingOpen, AssetID: "0198c0de-0001", Title: "Exploitable service with a very long descriptive title that must wrap across multiple rendered lines in the fixed-pitch table"},
			{RiskScore: 55, Severity: domain.SeverityHigh, CVEID: "CVE-2023-5678", Status: domain.FindingResolved, AssetID: "0198c0de-0002", Title: "TLS certificate expired"},
		},
		Assets: []domain.Asset{
			{ID: "0198c0de-0001", Hostname: "web-01", DeviceType: domain.DeviceServer, OSName: "Ubuntu 24.04", Exposure: domain.ExposureInternal, Criticality: domain.CriticalityHigh, RiskScore: 87},
			{ID: "0198c0de-0002", DeviceType: domain.DevicePrinter, OSName: "", Exposure: domain.ExposureInternal, Criticality: domain.CriticalityLow, RiskScore: 12},
		},
	}
	raw, ctype, err := renderPDF(d)
	if err != nil {
		t.Fatalf("renderPDF: %v", err)
	}
	if ctype != "application/pdf" {
		t.Fatalf("content type = %q", ctype)
	}
	if !bytes.HasPrefix(raw, []byte("%PDF-1.4")) {
		t.Fatal("missing PDF header")
	}
	if !bytes.Contains(raw, []byte("%%EOF")) {
		t.Fatal("missing EOF marker")
	}
	if !bytes.Contains(raw, []byte("/Type /Page")) || !bytes.Contains(raw, []byte("/Kids")) {
		t.Fatal("page tree missing")
	}
	// Grayscale must use the single-operand `g` operator; `rg` with one
	// operand is invalid PDF (real parsers reject it with "Too few args").
	if regexp.MustCompile(`(?m)^\d+(\.\d+)? rg$`).Match(raw) {
		t.Fatal("single-operand rg operator emitted (grayscale must use g)")
	}
	// The cursor is top-down: title baseline must be in the upper page
	// area (y ≈ margin), never pushed to the bottom by an inverted cursor.
	titleBaseline := regexp.MustCompile(`1 0 0 1 48\.0 (\d+\.\d) Tm`).FindStringSubmatch(string(raw))
	if titleBaseline == nil {
		t.Fatal("title text matrix missing")
	}
	if y, _ := strconv.ParseFloat(titleBaseline[1], 64); y < 700 {
		t.Fatalf("title baseline %s is inverted (must be near the top, >700)", titleBaseline[1])
	}

	// Parse the xref table and verify every offset points exactly at its object.
	s := string(raw)
	m := regexp.MustCompile(`startxref\s+(\d+)`).FindStringSubmatch(s)
	if m == nil {
		t.Fatal("startxref missing")
	}
	if pos, _ := strconv.Atoi(m[1]); s[pos:pos+4] != "xref" {
		t.Fatalf("startxref does not point at xref table")
	}
	lines := bytes.Split(raw, []byte("\n"))
	xrefLine := -1
	for i, l := range lines {
		if string(l) == "xref" {
			xrefLine = i
			break
		}
	}
	if xrefLine < 0 {
		t.Fatal("xref marker missing")
	}
	objRe := regexp.MustCompile(`^(\d+) 0 obj$`)
	// Row i = xrefLine+1 is the free entry ("0000000000 65535 f"); skip it.
	for i := xrefLine + 3; i < len(lines); i++ {
		l := string(lines[i])
		if l == "trailer" {
			break
		}
		parts := regexp.MustCompile(`^(\d{10}) 00000 n`).FindStringSubmatch(l)
		if parts == nil {
			t.Fatalf("malformed xref entry %q", l)
		}
		off, _ := strconv.Atoi(parts[1])
		if off <= 0 || off >= len(s) {
			t.Fatalf("xref offset %d out of range", off)
		}
		if !objRe.MatchString(string(bytes.Split(raw[off:], []byte("\n"))[0])) {
			t.Fatalf("xref offset %d does not point at an object header", off)
		}
	}
}
