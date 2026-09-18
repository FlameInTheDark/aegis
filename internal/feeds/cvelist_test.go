package feeds

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A realistic CVE JSON 5.0 record (trimmed): published state, CVSS 3.1,
// affected product with an official CPE and an affected version range.
const cve5Sample = `{
  "dataType": "CVE_RECORD",
  "dataVersion": "5.1",
  "cveMetadata": {
    "cveId": "CVE-2026-12345",
    "state": "PUBLISHED",
    "datePublished": "2026-01-15T17:15:00.000Z",
    "dateUpdated": "2026-02-01T14:00:00.000Z"
  },
  "containers": {
    "cna": {
      "descriptions": [
        {"lang": "en", "value": "A crafted request may cause a heap overflow in the example service."}
      ],
      "metrics": [
        {
          "format": "CVSS",
          "cvssV3_1": {
            "version": "3.1",
            "baseScore": 9.8,
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          }
        }
      ],
      "weaknesses": [
        {"description": [{"lang": "en", "value": "CWE-787"}]}
      ],
      "affected": [
        {
          "vendor": "example",
          "product": "example-service",
          "cpes": ["cpe:2.3:a:example:example-service:*:*:*:*:*:*:*:*"],
          "versions": [
            {"version": "2.0", "status": "affected", "lessThan": "2.7.3", "versionType": "semver"}
          ]
        }
      ],
      "references": [
        {"url": "https://example.com/advisory/12345"}
      ]
    }
  }
}`

func TestCVE5ToDomain(t *testing.T) {
	rec, err := decodeCVE5([]byte(cve5Sample))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	v, matches := cve5ToDomain(rec)
	if v == nil {
		t.Fatal("record should map to a vulnerability")
	}
	if v.CVEID != "CVE-2026-12345" {
		t.Errorf("cveId = %q", v.CVEID)
	}
	if v.State != "PUBLISHED" {
		t.Errorf("state = %q", v.State)
	}
	if v.CVSSv3 == nil || v.CVSSv3.Score != 9.8 {
		t.Errorf("cvssv3 = %+v", v.CVSSv3)
	}
	if len(v.CWE) != 1 || v.CWE[0] != "CWE-787" {
		t.Errorf("cwe = %v", v.CWE)
	}
	if len(v.References) != 1 || v.References[0] != "https://example.com/advisory/12345" {
		t.Errorf("references = %v", v.References)
	}
	if len(matches) != 1 {
		t.Fatalf("want 1 cpe match, got %d", len(matches))
	}
	m := matches[0]
	if m.Vendor != "example" || m.Product != "example-service" {
		t.Errorf("match identity = %+v", m)
	}
	// The affected-version range must land as explicit bounds so the
	// CPE_RANGE matcher can evaluate observed versions.
	if m.VersionEndExcl != "2.7.3" {
		t.Errorf("VersionEndExcl = %q, want 2.7.3", m.VersionEndExcl)
	}
}

func TestCVE5ReservedSkipped(t *testing.T) {
	rec, err := decodeCVE5([]byte(`{
      "dataType": "CVE_RECORD", "dataVersion": "5.1",
      "cveMetadata": {"cveId": "CVE-2026-99999", "state": "RESERVED"},
      "containers": {"cna": {"descriptions": [], "affected": []}}
    }`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	v, _ := cve5ToDomain(rec)
	if v != nil {
		t.Errorf("RESERVED record should be skipped, got %+v", v)
	}
}

func TestCVE5RejectedMapsState(t *testing.T) {
	rec, err := decodeCVE5([]byte(`{
      "dataType": "CVE_RECORD", "dataVersion": "5.1",
      "cveMetadata": {"cveId": "CVE-2026-88888", "state": "REJECTED"},
      "containers": {"cna": {"descriptions": [{"lang":"en","value":"unused"}], "affected": []}}
    }`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	v, _ := cve5ToDomain(rec)
	if v == nil || v.State != "REJECTED" {
		t.Errorf("REJECTED mapping = %+v", v)
	}
}

// ---------------------------------------------------------------------------
// Release discovery, sync planning and record-path classification.

// Expanded-assets HTML fragment shaped like GitHub's (asset hrefs inside a
// lazy-loaded fragment; one full snapshot, one hourly delta, release notes).
const cvelistAssetsPage = `<!DOCTYPE html>
<html><body>
<div class="Box">
  <a href="/CVEProject/cvelistV5/releases/download/cve_2026-09-16_1800Z/2026-09-16_all_CVEs_at_midnight.zip.zip">full</a>
  <a href="/CVEProject/cvelistV5/releases/download/cve_2026-09-16_1800Z/2026-09-16_delta_CVEs_at_1800Z.zip">delta</a>
  <a href="/CVEProject/cvelistV5/releases/download/cve_2026-09-16_1800Z/release_notes.md">notes</a>
</div>
</body></html>`

func TestResolveAssets(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/CVEProject/cvelistV5/releases/tag/cve_2026-09-16_1800Z", http.StatusFound)
	})
	// The redirect target must answer 200 so the client stops following.
	mux.HandleFunc("/CVEProject/cvelistV5/releases/tag/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html></html>"))
	})
	mux.HandleFunc("/releases/expanded_assets/cve_2026-09-16_1800Z", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(cvelistAssetsPage))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	job := &CVEListV5Job{BaseURL: srv.URL, Log: slog.Default()}
	assets, err := job.resolveAssets(context.Background())
	if err != nil {
		t.Fatalf("resolveAssets: %v", err)
	}
	if assets.Tag != "cve_2026-09-16_1800Z" {
		t.Errorf("tag = %q", assets.Tag)
	}
	if !strings.HasSuffix(assets.FullAsset, "/releases/download/cve_2026-09-16_1800Z/2026-09-16_all_CVEs_at_midnight.zip.zip") {
		t.Errorf("full asset = %q", assets.FullAsset)
	}
	if !strings.HasSuffix(assets.DeltaAsset, "/releases/download/cve_2026-09-16_1800Z/2026-09-16_delta_CVEs_at_1800Z.zip") {
		t.Errorf("delta asset = %q", assets.DeltaAsset)
	}
	if !strings.HasPrefix(assets.FullAsset, srv.URL) || !strings.HasPrefix(assets.DeltaAsset, srv.URL) {
		t.Errorf("asset URLs must be absolute: %q / %q", assets.FullAsset, assets.DeltaAsset)
	}
}

func TestResolveAssetsNoUsableAssets(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/CVEProject/cvelistV5/releases/tag/cve_2026-09-16_0000Z", http.StatusFound)
	})
	mux.HandleFunc("/releases/expanded_assets/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<a href="/CVEProject/cvelistV5/releases/download/x/release_notes.md">notes</a>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	job := &CVEListV5Job{BaseURL: srv.URL, Log: slog.Default()}
	if _, err := job.resolveAssets(context.Background()); err == nil {
		t.Fatal("expected error when the release exposes no CVE assets")
	}
}

func TestCVELISTPlan(t *testing.T) {
	now := time.Date(2026, 9, 16, 18, 53, 0, 0, time.UTC)
	morning := now.Add(-9 * time.Hour)    // synced 09:53 today
	yesterday := now.Add(-24 * time.Hour) // synced yesterday
	assets := &cvelistAssets{
		Tag:        "cve_2026-09-16_1800Z",
		FullAsset:  "https://x/2026-09-16_all_CVEs_at_midnight.zip.zip",
		DeltaAsset: "https://x/2026-09-16_delta_CVEs_at_1800Z.zip",
	}

	// Same-day sync: delta only — the whole corpus must not be re-pulled.
	plan, skip := cvelistPlan(now, morning, assets)
	if skip || len(plan) != 1 || plan[0].URL != assets.DeltaAsset {
		t.Errorf("same-day plan = %+v skip=%v, want delta-only", plan, skip)
	}

	// Bootstrap or day rollover: midnight snapshot + delta covers everything.
	plan, skip = cvelistPlan(now, yesterday, assets)
	if skip || len(plan) != 2 || plan[0].URL != assets.FullAsset || plan[1].URL != assets.DeltaAsset {
		t.Errorf("cross-day plan = %+v skip=%v, want full+delta", plan, skip)
	}
	plan, skip = cvelistPlan(now, time.Time{}, assets)
	if skip || len(plan) != 2 {
		t.Errorf("bootstrap plan = %+v skip=%v, want full+delta", plan, skip)
	}

	// Synced today but the release has no delta yet: nothing new, skip.
	stale := &cvelistAssets{Tag: "t", FullAsset: assets.FullAsset}
	plan, skip = cvelistPlan(now, morning, stale)
	if !skip || plan != nil {
		t.Errorf("same-day no-delta plan = %+v skip=%v, want skip", plan, skip)
	}

	// Cross-day without delta: full snapshot only (legacy layout).
	plan, _ = cvelistPlan(now, yesterday, stale)
	if len(plan) != 1 || plan[0].URL != assets.FullAsset {
		t.Errorf("cross-day no-delta plan = %+v, want full-only", plan)
	}
}

func TestIsCVELISTRecordPath(t *testing.T) {
	yes := []string{
		"cves/2024/1xxx/CVE-2024-1234.json",                // legacy asset root
		"cvelistV5-main/cves/2024/1xxx/CVE-2024-1234.json", // branch archive prefix
		"deltaCves/CVE-2023-24035.json",                    // daily delta
		"cvelistV5-main/deltaCves/CVE-2023-24035.json",     // branch archive delta
	}
	no := []string{
		"README.md",
		"schema/CVE_Record_Format.json",
		"baselineCVE/2026/baseline.json", // repo bookkeeping, not records
		"script/out.json",
	}
	for _, p := range yes {
		if !isCVELISTRecordPath(p) {
			t.Errorf("isCVELISTRecordPath(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if isCVELISTRecordPath(p) {
			t.Errorf("isCVELISTRecordPath(%q) = true, want false", p)
		}
	}
}

// The exact record shape from the field report: OpenSSH affected below
// 10.4 (versionType "custom", start "0"), discovered version
// "10.0p2 Debian 7" must land inside the range.
const cve5OpenSSHSample = `{
  "dataType": "CVE_RECORD", "dataVersion": "5.1",
  "cveMetadata": {"cveId": "CVE-2026-OPENSSH", "state": "PUBLISHED"},
  "containers": {
    "cna": {
      "affected": [
        {
          "defaultStatus": "unaffected",
          "product": "OpenSSH",
          "vendor": "OpenBSD",
          "versions": [
            {
              "lessThan": "10.4",
              "status": "affected",
              "version": "0",
              "versionType": "custom"
            }
          ]
        }
      ]
    }
  }
}`

func TestCVE5AffectedUserCase(t *testing.T) {
	rec, err := decodeCVE5([]byte(cve5OpenSSHSample))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	v, matches := cve5ToDomain(rec)
	if v == nil {
		t.Fatal("record should map to a vulnerability")
	}
	// The affected statement is stored verbatim for the CVE page.
	if len(v.Affected) != 1 {
		t.Fatalf("want 1 affected product, got %d", len(v.Affected))
	}
	aff := v.Affected[0]
	if aff.Vendor != "OpenBSD" || aff.Product != "OpenSSH" || aff.DefaultStatus != "unaffected" {
		t.Errorf("affected product = %+v", aff)
	}
	if len(aff.Versions) != 1 || aff.Versions[0].LessThan != "10.4" || aff.Versions[0].VersionType != "custom" {
		t.Errorf("affected versions = %+v", aff.Versions)
	}
	if len(matches) != 1 {
		t.Fatalf("want 1 cpe match, got %d", len(matches))
	}
	m := matches[0]
	if m.Vendor != "openbsd" || m.Product != "openssh" {
		t.Errorf("match identity = %+v", m)
	}
	if m.VersionStartIncl != "0" || m.VersionEndExcl != "10.4" {
		t.Errorf("bounds = [%q, %q), want [0, 10.4)", m.VersionStartIncl, m.VersionEndExcl)
	}
	if m.VersionType != "custom" {
		t.Errorf("versionType = %q, want custom", m.VersionType)
	}
}

func TestCVE5AffectedMultipleRangesFanOut(t *testing.T) {
	rec, err := decodeCVE5([]byte(`{
	  "dataType": "CVE_RECORD", "dataVersion": "5.1",
	  "cveMetadata": {"cveId": "CVE-2026-RANGES", "state": "PUBLISHED"},
	  "containers": {"cna": {"affected": [{
	    "vendor": "v", "product": "p",
	    "versions": [
	      {"version": "2.0", "lessThan": "2.5", "status": "affected", "versionType": "custom"},
	      {"version": "3.0", "lessThan": "3.2", "status": "affected", "versionType": "custom"}
	    ]
	  }]}}
	}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	_, matches := cve5ToDomain(rec)
	if len(matches) != 2 {
		t.Fatalf("each affected range must fan out to its own match, got %d", len(matches))
	}
	a, b := matches[0], matches[1]
	if a.VersionStartIncl != "2.0" || a.VersionEndExcl != "2.5" {
		t.Errorf("range 1 = [%q, %q)", a.VersionStartIncl, a.VersionEndExcl)
	}
	if b.VersionStartIncl != "3.0" || b.VersionEndExcl != "3.2" {
		t.Errorf("range 2 = [%q, %q)", b.VersionStartIncl, b.VersionEndExcl)
	}
}

func TestCVE5AffectedDefaultStatusComplement(t *testing.T) {
	rec, err := decodeCVE5([]byte(`{
	  "dataType": "CVE_RECORD", "dataVersion": "5.1",
	  "cveMetadata": {"cveId": "CVE-2026-COMPL", "state": "PUBLISHED"},
	  "containers": {"cna": {"affected": [{
	    "vendor": "v", "product": "p", "defaultStatus": "affected",
	    "versions": [
	      {"version": "2.5", "lessThanOrEqual": "2.5", "status": "unaffected", "versionType": "custom"}
	    ]
	  }]}}
	}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	_, matches := cve5ToDomain(rec)
	// Everything is affected except [.. 2.5] => affected [0,2.5) and (2.5,∞).
	if len(matches) != 2 {
		t.Fatalf("complement must produce 2 ranges, got %d: %+v", len(matches), matches)
	}
	low, high := matches[0], matches[1]
	if low.VersionEndExcl != "2.5" || low.VersionStartIncl != "" {
		t.Errorf("lower complement = [%q, %q)", low.VersionStartIncl, low.VersionEndExcl)
	}
	if high.VersionStartExcl != "2.5" || high.VersionEndExcl != "" {
		t.Errorf("upper complement = (%q, ∞), got end %q", high.VersionStartExcl, high.VersionEndExcl)
	}
}

func TestCVE5AffectedExactPin(t *testing.T) {
	rec, err := decodeCVE5([]byte(`{
	  "dataType": "CVE_RECORD", "dataVersion": "5.1",
	  "cveMetadata": {"cveId": "CVE-2026-PIN", "state": "PUBLISHED"},
	  "containers": {"cna": {"affected": [{
	    "vendor": "openssl", "product": "openssl",
	    "versions": [{"version": "1.0.2k", "status": "affected", "versionType": "custom"}]
	  }]}}
	}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	_, matches := cve5ToDomain(rec)
	if len(matches) != 1 || matches[0].Version != "1.0.2k" {
		t.Fatalf("exact pin must land as a pinned match, got %+v", matches)
	}
	if matches[0].VersionType != "custom" {
		t.Errorf("versionType = %q", matches[0].VersionType)
	}
}

func TestCVE5AffectedUnaffectedProductNoMatches(t *testing.T) {
	rec, err := decodeCVE5([]byte(`{
	  "dataType": "CVE_RECORD", "dataVersion": "5.1",
	  "cveMetadata": {"cveId": "CVE-2026-UNAFF", "state": "PUBLISHED"},
	  "containers": {"cna": {"affected": [{
	    "vendor": "v", "product": "p", "defaultStatus": "unaffected",
	    "versions": [{"version": "1.0", "lessThan": "2.0", "status": "unaffected", "versionType": "custom"}]
	  }]}}
	}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	_, matches := cve5ToDomain(rec)
	if len(matches) != 0 {
		t.Fatalf("a product the vendor declared unaffected must not become a candidate, got %+v", matches)
	}
}

func TestCVE5AffectedChangesSplitRange(t *testing.T) {
	rec, err := decodeCVE5([]byte(`{
	  "dataType": "CVE_RECORD", "dataVersion": "5.1",
	  "cveMetadata": {"cveId": "CVE-2026-CHG", "state": "PUBLISHED"},
	  "containers": {"cna": {"affected": [{
	    "vendor": "v", "product": "p",
	    "versions": [{
	      "version": "1.0", "lessThan": "2.0", "status": "affected", "versionType": "custom",
	      "changes": [{"at": "1.5", "status": "unaffected"}]
	    }]
	  }]}}
	}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	_, matches := cve5ToDomain(rec)
	// [1.0, 1.5) affected, [1.5, 2.0) unaffected => only the first survives.
	if len(matches) != 1 {
		t.Fatalf("want 1 affected segment, got %+v", matches)
	}
	if matches[0].VersionStartIncl != "1.0" || matches[0].VersionEndExcl != "1.5" {
		t.Errorf("segment = [%q, %q)", matches[0].VersionStartIncl, matches[0].VersionEndExcl)
	}
}
