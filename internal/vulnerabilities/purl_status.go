package vulnerabilities

import "github.com/FlameInTheDark/aegis/internal/domain"

// PackageAffected reports whether any cached OSV record affects the named
// package at the given version (F14). It runs the same range logic the
// correlator uses, so a per-row "queried, clean" status means exactly what
// the correlator would conclude. A version-less row can never produce a
// verdict, so the caller should leave it unqueried rather than claim clean.
func PackageAffected(records []domain.OSVRecord, pkg, version string) bool {
	if version == "" {
		return false
	}
	for _, rec := range records {
		if affected, _, _, _, _ := osvAffects(rec, pkg, version); affected {
			return true
		}
	}
	return false
}
