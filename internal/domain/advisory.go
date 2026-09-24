package domain

import "time"

// OSAdvisory is one distro advisory statement about one OS package in one
// release: the first fixed version (or "no fix yet") for a CVE, published
// under a distro advisory id (DSA/USN/RHSA/ALSA/...). It is the aegis
// equivalent of vuls' OVAL/gost detection plane — deterministic, distro-
// canonical, and therefore the highest-confidence match source.
type OSAdvisory struct {
	ID            string     `json:"id"`
	Family        string     `json:"family"`                   // canonical family key (fingerprinting.Distro*)
	Release       string     `json:"release"`                  // advisory release key ("12", "22.04", "9", "3.18")
	PackageName   string     `json:"package_name"`             // binary package name
	SourcePackage string     `json:"source_package,omitempty"` // when OVAL keys the source package
	FixedVersion  string     `json:"fixed_version,omitempty"`  // first fixed version; empty with NotFixedYet
	NotFixedYet   bool       `json:"not_fixed_yet"`
	CVEID         string     `json:"cve_id"`
	AdvisoryID    string     `json:"advisory_id"`
	AdvisoryURL   string     `json:"advisory_url,omitempty"`
	Severity      string     `json:"severity,omitempty"` // distro-declared, informational
	PublishedAt   *time.Time `json:"published_at,omitempty"`
	Source        string     `json:"source"` // oval | seed
	SourceVersion string     `json:"source_version,omitempty"`
	IngestedAt    time.Time  `json:"ingested_at"`
}

// VulnerableUnder reports whether pkgVersion is affected per this advisory
// under the distro's version grammar (versionType = deb/rpm/apk). A
// not-fixed-yet advisory affects every version of the package. Unparseable
// versions are never judged (incomparable) — the caller reports that
// honestly instead of guessing.
func (a *OSAdvisory) VulnerableUnder(pkgVersion string, compare func(a, b string) int) bool {
	if a.NotFixedYet {
		return true
	}
	if a.FixedVersion == "" || pkgVersion == "" {
		return false
	}
	return compare(pkgVersion, a.FixedVersion) < 0
}
