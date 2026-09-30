// Package sbom parses CycloneDX JSON documents into the platform's software
// inventory shape (F8: SBOM as an inventory source). Parsing is deliberately
// narrow — components only — and never executes anything from the document:
// a BOM is untrusted input, reviewed like a feed.
package sbom

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// MaxComponents bounds one document. The HTTP body cap is the first gate;
// this is the structural second gate so a pathological document with a
// million tiny components fails fast instead of exhausting memory.
const MaxComponents = 5000

// Component is the subset of a CycloneDX component the inventory needs.
type Component struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	PURL      string `json:"purl"`
	Publisher string `json:"publisher"`
}

type cycloneDXDoc struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Components  []Component `json:"components"`
}

// Package is one flattened inventory row.
type Package struct {
	Name      string
	Version   string
	PURL      string
	Ecosystem string
	Vendor    string
}

// Parse validates a CycloneDX JSON document and flattens its components
// into packages. Non-software component types (file, device, data, ...) are
// skipped; a document without usable components is an error so an
// accidental upload of the wrong file is visible, not silently empty.
func Parse(data []byte) ([]Package, error) {
	var doc cycloneDXDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid CycloneDX JSON: %w", err)
	}
	if !strings.EqualFold(doc.BOMFormat, "CycloneDX") {
		return nil, errors.New("not a CycloneDX document (bomFormat mismatch)")
	}
	if len(doc.Components) > MaxComponents {
		return nil, fmt.Errorf("document has %d components, cap is %d", len(doc.Components), MaxComponents)
	}
	out := make([]Package, 0, len(doc.Components))
	for _, c := range doc.Components {
		if !componentApplies(c.Type) {
			continue
		}
		p := Package{
			Name:    strings.TrimSpace(c.Name),
			Version: strings.TrimSpace(c.Version),
			PURL:    strings.TrimSpace(c.PURL),
			Vendor:  strings.TrimSpace(c.Publisher),
		}
		if p.PURL != "" {
			if name, version, eco := splitPURL(p.PURL); eco != "" {
				p.Ecosystem = eco
				// A Go module path IS the package identity — the purl path is
				// more precise than a bare component name. Elsewhere the
				// document's own name wins; the purl fills only gaps.
				if p.Name == "" || eco == "Go" {
					p.Name = osAwarePURLName(name, eco)
				}
				if p.Version == "" {
					p.Version = version
				}
			}
		}
		if p.Name == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, errors.New("no usable components in document")
	}
	return out, nil
}

func componentApplies(t string) bool {
	switch strings.ToLower(t) {
	case "", "application", "library", "framework", "operating-system", "container", "platform":
		return true
	}
	return false
}

// purlEcosystems maps CycloneDX purl types onto the ecosystem labels the
// vulnerability matcher routes on: OS-package families go to the distro
// advisory plane (os_*), language ecosystems use their OSV ecosystem names
// so package-scoped matching resolves them directly.
var purlEcosystems = map[string]string{
	"deb":      "os_debian",
	"rpm":      "os_rpm",
	"apk":      "os_alpine",
	"npm":      "npm",
	"pypi":     "PyPI",
	"golang":   "Go",
	"cargo":    "Cargo",
	"gem":      "RubyGems",
	"maven":    "Maven",
	"nuget":    "NuGet",
	"composer": "Packagist",
	"hex":      "hex",
	"conan":    "conan",
}

// osAwarePURLName strips the distro namespace for OS-package ecosystems:
// the advisory plane matches bare package names ("libc6", not
// "debian/libc6"). Language ecosystems keep the full path — a Go module or
// scoped npm package IS its path.
func osAwarePURLName(name, eco string) string {
	switch eco {
	case "os_debian", "os_rpm", "os_alpine":
		if i := strings.LastIndex(name, "/"); i >= 0 {
			return name[i+1:]
		}
	}
	return name
}

// splitPURL extracts name, version and ecosystem from a package URL
// (pkg:<type>/<namespace>/<name>@<version>). It returns an empty ecosystem
// for unknown types — the row still lands in the inventory with its purl,
// it just cannot match yet.
func splitPURL(purl string) (name, version, ecosystem string) {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return "", "", ""
	}
	rest = strings.TrimPrefix(rest, "//")
	typo, path, _ := strings.Cut(rest, "/")
	eco, ok := purlEcosystems[strings.ToLower(typo)]
	if !ok || path == "" {
		return "", "", ""
	}
	// Qualifiers come after the version ("...@2.36-9?arch=amd64") — strip
	// them before splitting off the version.
	if i := strings.Index(path, "?"); i >= 0 {
		path = path[:i]
	}
	// Version is the last unencoded '@'; scoped names carry '%40'.
	if i := strings.LastIndex(path, "@"); i >= 0 {
		version = path[i+1:]
		path = path[:i]
	}
	if unescaped, err := url.PathUnescape(path); err == nil {
		path = unescaped
	}
	return path, version, eco
}
