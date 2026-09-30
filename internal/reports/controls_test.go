package reports

import (
	"strings"
	"testing"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

func TestControlsCatalogParses(t *testing.T) {
	cat, err := Controls()
	if err != nil {
		t.Fatalf("Controls: %v", err)
	}
	if len(cat.Controls) == 0 {
		t.Fatal("catalog is empty")
	}
	if cat.CatalogVersion == "" {
		t.Fatal("catalog version missing")
	}
	for _, c := range cat.Controls {
		if c.ID == "" || c.Source == "" || c.Name == "" {
			t.Fatalf("control missing identity fields: %+v", c)
		}
	}
}

func TestMatchControlSeverity(t *testing.T) {
	cat, _ := Controls()
	var sevControl *ControlDef
	for i := range cat.Controls {
		if cat.Controls[i].ID == "CIS-7" {
			sevControl = &cat.Controls[i]
		}
	}
	if sevControl == nil {
		t.Fatal("CIS-7 control missing")
	}
	findings := []domain.Finding{
		{ID: "f1", Title: "OpenSSH outdated", Severity: domain.SeverityHigh, LastSeen: time.Now()},
		{ID: "f2", Title: "Info leak", Severity: domain.SeverityInfo, LastSeen: time.Now()},
		{ID: "f3", Title: "SMB exposed", Severity: domain.SeverityCritical, LastSeen: time.Now()},
	}
	row := matchControl(*sevControl, findings, nil)
	if row.MatchedCount != 2 {
		t.Fatalf("matched %d, want 2", row.MatchedCount)
	}
	if row.ObservedState != "findings mapped" {
		t.Fatalf("state: %s", row.ObservedState)
	}
}

func TestMatchControlTitleFragment(t *testing.T) {
	cat, _ := Controls()
	var mgmt *ControlDef
	for i := range cat.Controls {
		if cat.Controls[i].ID == "CIS-4.6" {
			mgmt = &cat.Controls[i]
		}
	}
	if mgmt == nil {
		t.Fatal("CIS-4.6 control missing")
	}
	row := matchControl(*mgmt, []domain.Finding{
		{ID: "f1", Title: "Exposed Management Port on router", Severity: domain.SeverityHigh},
		{ID: "f2", Title: "Unrelated", Severity: domain.SeverityHigh},
	}, nil)
	if row.MatchedCount != 1 {
		t.Fatalf("matched %d, want 1", row.MatchedCount)
	}
	if !strings.EqualFold(row.ObservedState, "findings mapped") {
		t.Fatalf("state: %s", row.ObservedState)
	}
}

func TestMatchControlKEVNilSetNeverFires(t *testing.T) {
	cat, _ := Controls()
	var kevControl *ControlDef
	for i := range cat.Controls {
		if cat.Controls[i].Match.KEV {
			kevControl = &cat.Controls[i]
		}
	}
	if kevControl == nil {
		t.Fatal("no KEV control in catalog")
	}
	row := matchControl(*kevControl, []domain.Finding{{ID: "f1", CVEID: "CVE-2026-1"}}, nil)
	if row.MatchedCount != 0 {
		t.Fatalf("KEV match must not fire without the set, got %d", row.MatchedCount)
	}
	if row.ObservedState != "no findings observed" {
		t.Fatalf("state: %s", row.ObservedState)
	}
	// With the set present, the CVE maps.
	row = matchControl(*kevControl, []domain.Finding{{ID: "f1", CVEID: "CVE-2026-1"}}, map[string]bool{"CVE-2026-1": true})
	if row.MatchedCount != 1 {
		t.Fatalf("KEV match should fire, got %d", row.MatchedCount)
	}
}
