// OVAL definitions parsing. Parses the distro OVAL feeds (Debian, Ubuntu, RHEL, Alpine) into
// os_advisories rows.
//
// The feeds are large (tens of MB up to ~1GB uncompressed), so this is a
// single streaming pass with xml.Decoder over token local-names — no
// namespace registration, no whole-document buffering. OVAL documents list
// <definitions> before <tests>/<objects>/<states>, and definitions reference
// tests by id, so definitions are buffered (small structs only) and resolved
// after the stream ends.
//
// Supported shapes (the ones the major distro feeds actually emit):
//
//	definition[class=vulnerability]
//	  metadata: title, description, reference (CVE + advisory refs),
//	            advisory/severity, issued date
//	  criteria: criterion test_ref="..." (any depth)
//	*_test:  <object object_ref="..."/> + <state state_ref="..."/>
//	*_object: <name>package</name>
//	*_state: <evr operation="less than">epoch:ver-rel</evr>  (deb/rpm)
//	         <version operation="less than">1.2.3-r0</version> (apk)
//
// A definition resolves to one advisory row per (package, CVE): fixed
// version from the state comparison value, or NotFixedYet when the test has
// no comparable fixed version (unpatched streams).
package feeds

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"
)

type ovalDefinition struct {
	id          string
	title       string
	description string
	advisoryID  string
	advisoryURL string
	severity    string
	issued      string
	cves        []string
	testRefs    []string
}

type ovalTest struct {
	id        string
	objectRef string
	stateRef  string
}

type ovalObject struct {
	id   string
	name string
}

type ovalState struct {
	id string
	// op is the comparison operation ("less than", "less than or equal",
	// "equals", "exists", ...). Only less-than variants yield a fixed
	// version; everything else (or no state) means affected without a fix.
	op    string
	value string
}

// advisoryRow is the parser's output shape — a domain.OSAdvisory without the
// surrogate id, which the repo assigns.
type advisoryRow struct {
	Family        string
	Release       string
	PackageName   string
	SourcePackage string
	FixedVersion  string
	NotFixedYet   bool
	CVEID         string
	AdvisoryID    string
	AdvisoryURL   string
	Severity      string
	PublishedAt   *time.Time
	Source        string
	SourceVersion string
}

// textTargets are the element local-names whose character data we capture.
const (
	textTitle       = "title"
	textDescription = "description"
	textSeverity    = "severity"
	textObjName     = "objname"
	textStateVal    = "stateval"
	textGenerator   = "generator"
)

// ParseOVAL resolves an OVAL definitions document into advisory rows.
// family and release are authoritative (the feed source config keys them —
// the same values os_advisories is queried by); platform strings in the
// document vary too much across distros to be trusted for release keys.
// source is recorded verbatim ("oval"); sourceVersion defaults to the
// document generator timestamp.
func ParseOVAL(r io.Reader, family, release, source, sourceVersion string) ([]advisoryRow, error) {
	defs := map[string]*ovalDefinition{}
	var order []string
	tests := map[string]*ovalTest{}
	objects := map[string]*ovalObject{}
	states := map[string]*ovalState{}
	genTimestamp := ""

	var (
		cur       *ovalDefinition
		curTest   *ovalTest
		curObject *ovalObject
		curState  *ovalState
		textFor   string
		text      strings.Builder
	)

	dec := xml.NewDecoder(r)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("oval: stream decode: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			local := localName(t.Name)
			switch {
			case local == "definition":
				cur = &ovalDefinition{id: attr(t, "id")}
				if cur.id != "" {
					defs[cur.id] = cur
					order = append(order, cur.id)
				}
			case local == "generated" && textFor == "":
				textFor = textGenerator // generator > timestamp
			case cur != nil && local == "title":
				textFor = textTitle
			case cur != nil && local == "description":
				textFor = textDescription
			case cur != nil && local == "severity":
				textFor = textSeverity
			case cur != nil && local == "issued":
				cur.issued = firstNonEmpty(attr(t, "date"), cur.issued)
			case cur != nil && local == "reference":
				refID := attr(t, "ref_id")
				if attr(t, "source") == "CVE" || looksLikeCVE(refID) {
					if refID != "" && !containsString(cur.cves, refID) {
						cur.cves = append(cur.cves, refID)
					}
				} else if cur.advisoryID == "" && refID != "" {
					cur.advisoryID = refID
					cur.advisoryURL = attr(t, "ref_url")
				}
			case cur != nil && local == "criterion":
				if tr := attr(t, "test_ref"); tr != "" {
					cur.testRefs = append(cur.testRefs, tr)
				}
			case cur == nil && strings.HasSuffix(local, "_test"):
				curTest = &ovalTest{id: attr(t, "id")}
			case cur == nil && strings.HasSuffix(local, "_object"):
				curObject = &ovalObject{id: attr(t, "id")}
			case cur == nil && strings.HasSuffix(local, "_state"):
				curState = &ovalState{id: attr(t, "id"), op: "exists"}
			case curTest != nil && local == "object":
				curTest.objectRef = attr(t, "object_ref")
			case curTest != nil && local == "state":
				curTest.stateRef = attr(t, "state_ref")
			case curObject != nil && local == "name":
				textFor = textObjName
			case curState != nil && (local == "evr" || local == "version"):
				curState.op = firstNonEmpty(attr(t, "operation"), "exists")
				textFor = textStateVal
			}
		case xml.CharData:
			if textFor != "" {
				text.Write(t)
			}
		case xml.EndElement:
			local := localName(t.Name)
			switch textFor {
			case textTitle:
				if cur != nil && cur.title == "" {
					cur.title = strings.TrimSpace(text.String())
				}
				text.Reset()
				textFor = ""
			case textDescription:
				if cur != nil {
					cur.description = truncateText(strings.TrimSpace(text.String()), 500)
				}
				text.Reset()
				textFor = ""
			case textSeverity:
				if cur != nil && cur.severity == "" {
					cur.severity = strings.ToLower(strings.TrimSpace(text.String()))
				}
				text.Reset()
				textFor = ""
			case textObjName:
				if curObject != nil && curObject.name == "" {
					curObject.name = strings.TrimSpace(text.String())
				}
				text.Reset()
				textFor = ""
			case textStateVal:
				if curState != nil && curState.value == "" {
					curState.value = strings.TrimSpace(text.String())
				}
				text.Reset()
				textFor = ""
			case textGenerator:
				genTimestamp = strings.TrimSpace(text.String())
				text.Reset()
				textFor = ""
			}
			switch {
			case cur != nil && local == "definition":
				cur = nil
			case curTest != nil && strings.HasSuffix(local, "_test"):
				if curTest.id != "" {
					tests[curTest.id] = curTest
				}
				curTest = nil
			case curObject != nil && strings.HasSuffix(local, "_object"):
				if curObject.id != "" {
					objects[curObject.id] = curObject
				}
				curObject = nil
			case curState != nil && strings.HasSuffix(local, "_state"):
				if curState.id != "" {
					states[curState.id] = curState
				}
				curState = nil
			}
		}
	}
	if sourceVersion == "" {
		sourceVersion = genTimestamp
	}

	out := make([]advisoryRow, 0, len(order))
	for _, id := range order {
		d := defs[id]
		if len(d.cves) == 0 || len(d.testRefs) == 0 {
			continue
		}
		advisoryID := d.advisoryID
		if advisoryID == "" {
			advisoryID = d.title // last resort: titles carry DSA/USN/RHSA ids
		}
		var published *time.Time
		if ts, err := time.Parse("2006-01-02", firstNonEmpty(d.issued, dateOf(genTimestamp))); err == nil {
			published = &ts
		}
		for _, tr := range d.testRefs {
			tes, ok := tests[tr]
			if !ok {
				continue
			}
			obj := objects[tes.objectRef]
			st := states[tes.stateRef]
			if obj == nil || obj.name == "" {
				continue
			}
			for _, cve := range d.cves {
				row := advisoryRow{
					Family: family, Release: release, PackageName: obj.name,
					CVEID: cve, AdvisoryID: advisoryID, AdvisoryURL: d.advisoryURL,
					Severity: d.severity, PublishedAt: published,
					Source: source, SourceVersion: sourceVersion,
				}
				if st != nil && isLessOp(st.op) && st.value != "" {
					row.FixedVersion = stripZeroEpoch(st.value)
				} else {
					row.NotFixedYet = true
				}
				out = append(out, row)
			}
		}
	}
	return out, nil
}

func isLessOp(op string) bool {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "less than", "less than or equal":
		return true
	}
	return false
}

// stripZeroEpoch normalizes OVAL evr values ("0:1.2.3-4") to the shape the
// installed-package inventories use ("1.2.3-4"). Non-zero epochs are kept —
// they matter for ordering.
func stripZeroEpoch(v string) string {
	if i := strings.IndexByte(v, ':'); i > 0 && v[:i] == "0" {
		return v[i+1:]
	}
	return v
}

func looksLikeCVE(s string) bool {
	return len(s) > 8 && (strings.HasPrefix(s, "CVE-") || strings.HasPrefix(s, "cve-"))
}

func localName(n xml.Name) string {
	if i := strings.IndexByte(n.Local, ':'); i >= 0 {
		return n.Local[i+1:]
	}
	return n.Local
}

func attr(t xml.StartElement, name string) string {
	for _, a := range t.Attr {
		if localName(a.Name) == name {
			return a.Value
		}
	}
	return ""
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func truncateText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func dateOf(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ""
}
