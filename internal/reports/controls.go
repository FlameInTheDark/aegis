package reports

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// F13: the control catalog is data, reviewed like a feed — never code and
// never presented as a certification. Each control maps to the weakness
// classes the platform can actually observe (findings), with explicit match
// rules so the mapping is auditable.

//go:embed controls.json
var controlsJSON []byte

// ControlMatch is the rule set deciding which findings evidence a control.
type ControlMatch struct {
	TitleAny    []string `json:"title_any,omitempty"`
	SeverityAny []string `json:"severity_any,omitempty"`
	KEV         bool     `json:"kev,omitempty"`
}

// ControlDef is one catalog entry.
type ControlDef struct {
	ID          string       `json:"id"`
	Source      string       `json:"source"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Match       ControlMatch `json:"match"`
}

type controlCatalog struct {
	CatalogVersion string       `json:"catalog_version"`
	Note           string       `json:"note"`
	Controls       []ControlDef `json:"controls"`
}

var (
	controlsOnce sync.Once
	controlsVal  controlCatalog
	controlsErr  error
)

// Controls returns the embedded control catalog (parsed once).
func Controls() (controlCatalog, error) {
	controlsOnce.Do(func() {
		controlsErr = json.Unmarshal(controlsJSON, &controlsVal)
		if controlsErr != nil {
			controlsErr = fmt.Errorf("parse embedded control catalog: %w", controlsErr)
		}
	})
	return controlsVal, controlsErr
}

// ControlRow is one report row: a control, the findings that map to it, and
// the honesty note that "no findings" means "no observed violations", not
// "control satisfied".
type ControlRow struct {
	ID            string           `json:"id"`
	Source        string           `json:"source"`
	Name          string           `json:"name"`
	Description   string           `json:"description"`
	MatchedCount  int              `json:"matched_findings"`
	ObservedState string           `json:"observed_state"` // "findings mapped" | "no findings observed"
	Findings      []domain.Finding `json:"findings,omitempty"`
}

// matchControl applies one control's match rule to a finding set. kevSet may
// be nil when the KEV index is unavailable — the rule then simply cannot
// fire, which is honest (the report says "no findings observed").
func matchControl(def ControlDef, findings []domain.Finding, kevSet map[string]bool) ControlRow {
	row := ControlRow{ID: def.ID, Source: def.Source, Name: def.Name, Description: def.Description}
	for _, f := range findings {
		matched := false
		switch {
		case def.Match.KEV:
			matched = kevSet != nil && f.CVEID != "" && kevSet[f.CVEID]
		case len(def.Match.SeverityAny) > 0:
			for _, s := range def.Match.SeverityAny {
				if strings.EqualFold(s, string(f.Severity)) {
					matched = true
					break
				}
			}
		case len(def.Match.TitleAny) > 0:
			t := strings.ToLower(f.Title)
			for _, frag := range def.Match.TitleAny {
				if strings.Contains(t, strings.ToLower(frag)) {
					matched = true
					break
				}
			}
		}
		if matched {
			row.MatchedCount++
			if len(row.Findings) < 50 {
				row.Findings = append(row.Findings, f)
			}
		}
	}
	if row.MatchedCount > 0 {
		row.ObservedState = "findings mapped"
	} else {
		row.ObservedState = "no findings observed"
	}
	return row
}
