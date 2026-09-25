package feeds

import (
	"encoding/json"
	"testing"
	"time"
)

// nvdToDomain must parse the CPE identity (vendor/product/version) out of
// every applicability criterion. Before the identity fix it stored only the
// raw criteria string, so the vendor/product columns stayed blank and
// CandidateCVEsByProduct — the matcher's candidate source — was blind to
// 99%+ of NVD applicability (including every OpenSSH CVE).
func TestNVDToDomainIndexesCPEIdentity(t *testing.T) {
	payload := map[string]any{
		"vulnerabilities": []any{
			map[string]any{
				"cve": map[string]any{
					"id": "CVE-2026-1234",
					"configurations": []any{
						map[string]any{
							"nodes": []any{
								map[string]any{
									"cpeMatch": []any{
										map[string]any{
											"vulnerable":          true,
											"criteria":            "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*:*",
											"versionEndExcluding": "10.5",
										},
										map[string]any{
											"vulnerable": true,
											"criteria":   "cpe:2.3:a:openbsd:openssh:10.0p1:*:*:*:*:*:*:*:*",
										},
										map[string]any{
											"vulnerable":          true,
											"criteria":            "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*:*",
											"versionEndExcluding": "10.5",
										},
										map[string]any{
											"vulnerable": false,
											"criteria":   "cpe:2.3:a:openbsd:openssh:9.9:*:*:*:*:*:*:*:*",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var resp nvdResp
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if len(resp.Vulnerabilities) != 1 {
		t.Fatalf("payload must carry one CVE, got %d", len(resp.Vulnerabilities))
	}
	v := nvdToDomain(resp.Vulnerabilities[0].CVE, time.Now())
	if len(v.CPEMatches) != 2 {
		t.Fatalf("CPEMatches = %d (negated and duplicate rows must be dropped), want 2", len(v.CPEMatches))
	}
	ranged := v.CPEMatches[0]
	if ranged.Vendor != "openbsd" || ranged.Product != "openssh" {
		t.Errorf("ranged identity = %q/%q, want openbsd/openssh", ranged.Vendor, ranged.Product)
	}
	if ranged.VersionEndExcl != "10.5" {
		t.Errorf("ranged bound = %q, want 10.5", ranged.VersionEndExcl)
	}
	pinned := v.CPEMatches[1]
	if pinned.Version != "10.0p1" {
		t.Errorf("pinned version = %q, want 10.0p1", pinned.Version)
	}
	if pinned.Vendor != "openbsd" || pinned.Product != "openssh" {
		t.Errorf("pinned identity = %q/%q, want openbsd/openssh", pinned.Vendor, pinned.Product)
	}
}
