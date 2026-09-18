// affected.go turns CVE List v5 "affected" statements into stored display
// data (domain.AffectedProduct) and into machine-matchable CPE matches
// with correct per-range version bounds (spec §32).
//
// The subtleties this file exists for — everything the naive "take
// lessThan and call it a day" approach gets wrong:
//
//   - a version entry with only "version" pins that exact version
//   - "version" is the INCLUSIVE start of a range, not decoration
//     ("8.2 < v < 9.0" must not match 7.4)
//   - several affected ranges in one entry must fan out into several CPE
//     matches, not overwrite each other
//   - defaultStatus "affected" means EVERY version is affected except the
//     ones explicitly marked "unaffected" (complement semantics)
//   - "changes" flip the status from a version onward inside a range
//   - "versionType" names the ordering rules (custom/semver/rpm/deb/…)
//     and travels with every match so the comparator picks the right one
package feeds

import (
	"sort"
	"strings"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/fingerprinting"
)

// maxAffectedMatches caps the CPE-match fan-out per affected product
// entry. Real-world entries stay far below this; the cap only guards
// against pathological feed data bloating the candidate index.
const maxAffectedMatches = 96

// verBound is one end of a version interval. set=false means "no bound".
type verBound struct {
	val  string
	incl bool // inclusive (>= / <=) vs exclusive (> / <)
	set  bool
}

// verInterval is a version interval with a status. pinned != "" marks an
// exact-version statement (start == end == that version).
type verInterval struct {
	start, end  verBound
	pinned      string
	status      string // affected | unaffected | unknown
	versionType string
}

// cve5VersionChange is the changes[] element of a version entry.
type cve5VersionChange struct {
	At     string `json:"at"`
	Status string `json:"status"`
}

// toVersionChanges converts the anonymous changes[] slice of the parsed
// record into the named type.
func toVersionChanges(in []struct {
	At     string `json:"at"`
	Status string `json:"status"`
}) []cve5VersionChange {
	if len(in) == 0 {
		return nil
	}
	out := make([]cve5VersionChange, 0, len(in))
	for _, ch := range in {
		out = append(out, cve5VersionChange{At: ch.At, Status: ch.Status})
	}
	return out
}

// affectedToDomain maps affected entries to the stored display model
// (rendered verbatim on the CVE page).
func affectedToDomain(list []cve5Affected) []domain.AffectedProduct {
	if len(list) == 0 {
		return nil
	}
	out := make([]domain.AffectedProduct, 0, len(list))
	for _, aff := range list {
		if aff.Vendor == "" && aff.Product == "" {
			continue
		}
		p := domain.AffectedProduct{
			Vendor:        aff.Vendor,
			Product:       aff.Product,
			DefaultStatus: aff.DefaultStatus,
			CPEs:          aff.CPEs,
			Platforms:     aff.Platforms,
		}
		for _, ver := range aff.Versions {
			av := domain.AffectedVersion{
				Version:         ver.Version,
				Status:          ver.Status,
				LessThan:        ver.LessThan,
				LessThanOrEqual: ver.LessThanOrEqual,
				VersionType:     ver.VersionType,
			}
			for _, ch := range ver.Changes {
				av.Changes = append(av.Changes, domain.AffectedChange{At: ch.At, Status: ch.Status})
			}
			p.Versions = append(p.Versions, av)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// affectedToCPEMatches materializes affected entries into CPE matches —
// one match per affected version range per base CPE identity, each with
// its own start/end bounds and versionType. These rows are what the
// candidate query and the range evaluator consume.
func affectedToCPEMatches(list []cve5Affected) []domain.CPEMatch {
	var out []domain.CPEMatch
	for _, aff := range list {
		if aff.Vendor == "" || aff.Product == "" {
			continue
		}
		// Base CPE identities: official CPE strings when the CNA supplied
		// them, otherwise one synthesized vendor/product wildcard.
		cpes := aff.CPEs
		if len(cpes) == 0 {
			cpes = []string{"cpe:2.3:a:" + sanitizeCPEComponent(aff.Vendor) + ":" + sanitizeCPEComponent(aff.Product) + ":*:*:*:*:*:*:*:*"}
		}
		var bases []fingerprinting.CPE
		seenBase := map[string]bool{}
		for _, s := range cpes {
			c, ok := fingerprinting.ParseCPE(s)
			if !ok || seenBase[s] {
				continue
			}
			seenBase[s] = true
			bases = append(bases, c)
		}
		if len(bases) == 0 {
			continue
		}
		vendor, product := strings.ToLower(bases[0].Vendor), strings.ToLower(bases[0].Product)

		intervals := affectedEntryIntervals(aff)
		affected := affectedIntervalSet(aff, intervals)
		seen := map[string]bool{}
		add := func(m domain.CPEMatch) {
			if len(out) >= maxAffectedMatches {
				return
			}
			m.Vendor, m.Product = vendor, product
			key := strings.Join([]string{m.CPE, m.Version, m.VersionStartIncl, m.VersionStartExcl, m.VersionEndIncl, m.VersionEndExcl}, "\x1f")
			if seen[key] {
				return
			}
			seen[key] = true
			out = append(out, m)
		}

		for _, iv := range affected {
			for _, b := range bases {
				if iv.pinned != "" {
					c2 := b
					c2.Version = iv.pinned
					add(domain.CPEMatch{CPE: fingerprinting.FormatCPE(c2), Version: iv.pinned, VersionType: iv.versionType})
					continue
				}
				if b.Version != "" {
					continue // a pinned CPE base is an exact statement, never a range
				}
				m := domain.CPEMatch{CPE: fingerprinting.FormatCPE(b), VersionType: iv.versionType}
				if iv.start.set {
					if iv.start.incl {
						m.VersionStartIncl = iv.start.val
					} else {
						m.VersionStartExcl = iv.start.val
					}
				}
				if iv.end.set {
					if iv.end.incl {
						m.VersionEndIncl = iv.end.val
					} else {
						m.VersionEndExcl = iv.end.val
					}
				}
				add(m)
				if len(out) >= maxAffectedMatches {
					break
				}
			}
		}

		// Nothing definitively affected (no version statements at all, or only
		// "unknown" applicability): unless the vendor declared the product
		// unaffected, keep a versionless candidate — the matcher reports it
		// as "potential" only, never a confirmed vulnerability.
		if len(affected) == 0 && !strings.EqualFold(aff.DefaultStatus, domain.AffectedStatusUnaffected) {
			for _, b := range bases {
				if b.Version != "" {
					continue
				}
				add(domain.CPEMatch{CPE: fingerprinting.FormatCPE(b)})
			}
		}
	}
	return out
}

// affectedIntervalSet decides which intervals are affected for one product
// entry, applying defaultStatus complement semantics:
//
//   - entries marked "affected" (explicitly or via defaultStatus) are taken
//     as-is, except when defaultStatus is "affected" AND unaffected
//     carve-outs exist — then the affected set is the complement of the
//     unaffected intervals (plus the explicit affected ones).
//   - defaultStatus "unaffected" with no affected entries ⇒ nothing.
func affectedIntervalSet(aff cve5Affected, intervals []verInterval) []verInterval {
	var affectedList, unaffectedList []verInterval
	for _, iv := range intervals {
		switch iv.status {
		case domain.AffectedStatusAffected:
			affectedList = append(affectedList, iv)
		case domain.AffectedStatusUnaffected:
			unaffectedList = append(unaffectedList, iv)
		}
	}
	switch {
	case strings.EqualFold(aff.DefaultStatus, domain.AffectedStatusAffected) && len(unaffectedList) > 0:
		gaps, ok := complement(unaffectedList, intervalVersionType(intervals))
		if !ok {
			// Incomparable bounds — refuse to guess the complement and fall
			// back to the explicit affected statements only.
			return affectedList
		}
		return append(affectedList, gaps...)
	default:
		// Explicit affected statements carry the semantics. When the vendor
		// declared the whole product affected but gave no unaffected carve-out
		// and no ranges, the empty result is handled downstream as a
		// versionless "potential" candidate.
		return affectedList
	}
}

// intervalVersionType picks the versionType for complement ordering (the
// first non-empty one; entries of one product share their scheme).
func intervalVersionType(intervals []verInterval) string {
	for _, iv := range intervals {
		if iv.versionType != "" {
			return iv.versionType
		}
	}
	return fingerprinting.VersionTypeCustom
}

// affectedEntryIntervals converts the version statements of one affected
// entry into intervals with per-statement status, splitting at "changes".
func affectedEntryIntervals(aff cve5Affected) []verInterval {
	defaultStatus := strings.ToLower(aff.DefaultStatus)
	var out []verInterval
	for _, ver := range aff.Versions {
		status := strings.ToLower(ver.Status)
		if status == "" {
			status = defaultStatus
		}
		if status == "" {
			status = domain.AffectedStatusUnknown
		}
		iv := verInterval{status: status, versionType: ver.VersionType}
		switch {
		case ver.LessThan == "" && ver.LessThanOrEqual == "":
			if ver.Version == "" {
				continue // neither pin nor range: nothing versionable
			}
			iv.pinned = ver.Version
		default:
			if ver.Version != "" {
				iv.start = verBound{val: ver.Version, incl: true, set: true}
			}
			if ver.LessThan != "" {
				iv.end = verBound{val: ver.LessThan, incl: false, set: true}
			} else {
				iv.end = verBound{val: ver.LessThanOrEqual, incl: true, set: true}
			}
		}
		out = append(out, splitChanges(iv, toVersionChanges(ver.Changes))...)
	}
	return out
}

// splitChanges cuts an interval at each changes[].at boundary; segments
// from a change point onward carry the changed status. The base status
// governs up to the first change. When change points cannot be ordered
// against the interval bounds the split is refused (whole range keeps the
// base status) rather than guessed.
func splitChanges(iv verInterval, changes []cve5VersionChange) []verInterval {
	if len(changes) == 0 {
		return []verInterval{iv}
	}
	vt := iv.versionType
	if iv.pinned != "" {
		iv.status = effectiveStatusAt(iv.pinned, iv.status, changes, vt)
		return []verInterval{iv}
	}
	cs := append([]cve5VersionChange(nil), changes...)
	sort.SliceStable(cs, func(a, b int) bool {
		return fingerprinting.CompareTyped(cs[a].At, cs[b].At, vt) < 0
	})
	// Every change point must be orderable and inside the interval.
	for _, ch := range cs {
		if strings.TrimSpace(ch.At) == "" {
			return []verInterval{iv}
		}
		if iv.start.set {
			switch fingerprinting.CompareTyped(ch.At, iv.start.val, vt) {
			case 2:
				return []verInterval{iv}
			case -1:
				return []verInterval{iv}
			}
		}
		if iv.end.set {
			switch fingerprinting.CompareTyped(ch.At, iv.end.val, vt) {
			case 2:
				return []verInterval{iv}
			case 0:
				// change at the interval end: no in-range versions follow it
				if iv.end.incl {
					return []verInterval{iv}
				}
			case 1:
				return []verInterval{iv}
			}
		}
	}
	segs := []verInterval{}
	cur := iv.start
	curStatus := iv.status
	for _, ch := range cs {
		if cur.set && fingerprinting.CompareTyped(ch.At, cur.val, vt) == 0 && !cur.incl {
			// change exactly at an exclusive start: applies from here
			curStatus = strings.ToLower(ch.Status)
			continue
		}
		segs = append(segs, verInterval{
			start: cur, end: verBound{val: ch.At, incl: false, set: true},
			status: curStatus, versionType: iv.versionType,
		})
		cur = verBound{val: ch.At, incl: true, set: true}
		curStatus = strings.ToLower(ch.Status)
	}
	if !iv.end.set || !cur.set || fingerprinting.CompareTyped(cur.val, iv.end.val, vt) < 0 || !iv.end.incl {
		segs = append(segs, verInterval{start: cur, end: iv.end, status: curStatus, versionType: iv.versionType})
	}
	return segs
}

// effectiveStatusAt resolves the status of an exact version under a base
// status plus ordered changes (the last change at or below the version wins).
func effectiveStatusAt(version, base string, changes []cve5VersionChange, vt string) string {
	st := base
	cs := append([]cve5VersionChange(nil), changes...)
	sort.SliceStable(cs, func(a, b int) bool {
		return fingerprinting.CompareTyped(cs[a].At, cs[b].At, vt) < 0
	})
	for _, ch := range cs {
		switch fingerprinting.CompareTyped(version, ch.At, vt) {
		case 0, 1:
			if ch.Status != "" {
				st = strings.ToLower(ch.Status)
			}
		}
	}
	return st
}

// complement computes the intervals NOT covered by the given ones over the
// whole version line — the affected set when defaultStatus is "affected"
// and the feed declares unaffected carve-outs. ok=false means the bounds
// could not be ordered (mixed/unknown schemes); the caller then refuses to
// guess.
func complement(covers []verInterval, vt string) (gaps []verInterval, ok bool) {
	// Orderable check across every bound first — any incomparable pair
	// aborts the whole computation.
	for i := range covers {
		iv := &covers[i]
		if iv.start.set && iv.end.set {
			switch fingerprinting.CompareTyped(iv.start.val, iv.end.val, vt) {
			case 2:
				return nil, false
			case 1:
				return nil, false // inverted interval: refuse
			}
		}
	}
	sort.SliceStable(covers, func(a, b int) bool {
		x, y := covers[a], covers[b]
		if !x.start.set && y.start.set {
			return true
		}
		if !x.start.set || !y.start.set {
			return false
		}
		return fingerprinting.CompareTyped(x.start.val, y.start.val, vt) < 0
	})
	var cur verBound // unset = from the very beginning
	for i := range covers {
		iv := covers[i]
		// Gap between cur and this interval's start?
		if iv.start.set {
			emit := false
			if !cur.set {
				emit = true
			} else {
				switch fingerprinting.CompareTyped(iv.start.val, cur.val, vt) {
				case 1:
					emit = true
				case 0:
					// equal bounds: a point gap only when the cover starts
					// inclusive after an inclusive cur would be empty; the
					// non-empty point case is start exclusive vs cur inclusive
					emit = !iv.start.incl && cur.incl
				}
			}
			if emit {
				gaps = append(gaps, verInterval{
					start:       verBound{val: cur.val, incl: !cur.incl, set: cur.set},
					end:         verBound{val: iv.start.val, incl: !iv.start.incl, set: true},
					status:      domain.AffectedStatusAffected,
					versionType: vt,
				})
			}
		} else if !iv.end.set {
			// Covers everything from the beginning: no gaps at all.
			return nil, true
		}
		// Advance cur past this interval's end.
		if !iv.end.set {
			return nil, true // open-ended cover: nothing after it
		}
		if !cur.set {
			cur = verBound{val: iv.end.val, incl: iv.end.incl, set: true}
		} else {
			switch fingerprinting.CompareTyped(iv.end.val, cur.val, vt) {
			case 1:
				cur = verBound{val: iv.end.val, incl: iv.end.incl, set: true}
			case 0:
				cur.incl = cur.incl || iv.end.incl
			}
		}
	}
	if cur.set {
		gaps = append(gaps, verInterval{
			start:       verBound{val: cur.val, incl: !cur.incl, set: true},
			status:      domain.AffectedStatusAffected,
			versionType: vt,
		})
	}
	return gaps, true
}
