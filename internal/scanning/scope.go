// Package scanning contains the scan orchestrator and network scope
// safety validation. Every scan must define explicit
// scope; the platform normalizes, validates and rejects dangerous or
// invalid targets before a single packet is sent.
package scanning

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ScopeValidation is the result of validating a requested scope.
type ScopeValidation struct {
	Targets        []string `json:"targets"`         // normalized CIDRs/hosts
	TotalAddresses int      `json:"total_addresses"` // expanded address count
	Private        bool     `json:"private"`         // all targets in private ranges
	Warnings       []string `json:"warnings,omitempty"`
	Errors         []string `json:"errors,omitempty"`
}

// maxScopeAddresses caps accidental huge scopes (enforce max target counts).
const maxScopeAddresses = 262144 // /14-ish; hard ceiling, profiles cap lower

var (
	privateV4 = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10"}
	privateV6 = []string{"fc00::/7", "fe80::/10", "::1/128"}
)

// ValidateScope normalizes and validates the requested target set.
// allowPublic=false rejects any scope containing public addresses unless
// the deployment explicitly enables public scanning (spec: never scan
// arbitrary Internet ranges by default).
func ValidateScope(cidrs, ipRanges, hostnames, denylist []string, allowPublic bool, maxTargets int) (*ScopeValidation, error) {
	v := &ScopeValidation{}
	seen := map[string]bool{}
	add := func(t string) {
		if !seen[t] {
			seen[t] = true
			v.Targets = append(v.Targets, t)
		}
	}

	check := func(cidr string) error {
		// Bare IPs are valid targets: "192.168.1.1" (or "::1") is treated as
		// the single-address CIDR ip/32 (ip/128). Users type a plain address
		// into the scan form far more often than a prefix — rejecting it as
		// an "invalid CIDR" made single-host trace scans impossible.
		if !strings.Contains(cidr, "/") {
			if ip := net.ParseIP(cidr); ip != nil {
				v.TotalAddresses++
				if isPublic(ip) && !allowPublic {
					v.Errors = append(v.Errors, fmt.Sprintf("%s contains public addresses; public scanning is disabled", cidr))
				}
				return nil
			}
		}
		ip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid CIDR or IP %q", cidr)
		}
		ones, bits := ipnet.Mask.Size()
		v.TotalAddresses += 1 << (bits - ones)
		if isPublic(ip) && !allowPublic {
			v.Errors = append(v.Errors, fmt.Sprintf("%s contains public addresses; public scanning is disabled", cidr))
		}
		return nil
	}

	// processRange validates one "start-end" range (full IPs or last-octet
	// shorthand) and expands it into CIDR blocks. Ranges arrive mixed into
	// the CIDR list because users type them into the same scan-form field;
	// the expansion keeps every downstream consumer uniform (nmap argv
	// cannot parse "ip-ip" pairs, denylist math is CIDR-based, and scope
	// storage stays canonical).
	processRange := func(r string) {
		lo, hi, err := parseRange(r)
		if err != nil {
			v.Errors = append(v.Errors, err.Error())
			return
		}
		n := ipRangeSize(lo, hi) + 1
		if n < 0 {
			v.Errors = append(v.Errors, fmt.Sprintf("invalid range %q: end before start", r))
			return
		}
		v.TotalAddresses += n
		if isPublic(lo) && !allowPublic {
			v.Errors = append(v.Errors, fmt.Sprintf("%s contains public addresses; public scanning is disabled", r))
		}
		for _, c := range rangeToCIDRs(lo, hi) {
			add(c)
		}
	}

	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// Range-looking entries are tried as ranges first: anything that
		// parses as start-end must never reach the CIDR parser, which
		// would reject it with "invalid CIDR or IP ...; scope is empty".
		if strings.Contains(c, "-") {
			if _, _, perr := parseRange(c); perr == nil {
				processRange(c)
				continue
			}
		}
		if err := check(c); err != nil {
			v.Errors = append(v.Errors, err.Error())
			continue
		}
		add(c)
	}
	for _, r := range ipRanges {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		processRange(r)
	}
	for _, h := range hostnames {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if isSuspiciousHostname(h) {
			v.Errors = append(v.Errors, fmt.Sprintf("invalid or unsafe hostname %q", h))
			continue
		}
		add(h)
	}

	if v.TotalAddresses > maxScopeAddresses {
		v.Errors = append(v.Errors, fmt.Sprintf("scope expands to %d addresses which exceeds the hard ceiling of %d", v.TotalAddresses, maxScopeAddresses))
	}
	if maxTargets > 0 && v.TotalAddresses > maxTargets {
		v.Errors = append(v.Errors, fmt.Sprintf("scope expands to %d addresses which exceeds the profile limit of %d", v.TotalAddresses, maxTargets))
	}
	if v.TotalAddresses == 0 {
		v.Errors = append(v.Errors, "scope is empty")
	}

	if !allowPublic && len(v.Errors) == 0 {
		v.Private = allPrivate(v.Targets)
	} else {
		v.Private = allPrivate(v.Targets)
	}
	if !v.Private {
		v.Warnings = append(v.Warnings, "Scope includes non-private address space. Verify you are authorized to assess every target.")
	}
	if len(v.Errors) > 0 {
		return v, fmt.Errorf("scope validation failed: %s", strings.Join(v.Errors, "; "))
	}
	return v, nil
}

// FilterDenied removes targets overlapping the denylist. Denylist wins
// over everything (spec: allowlist/denylist support).
func FilterDenied(targets, denylist []string) []string {
	if len(denylist) == 0 {
		return targets
	}
	var denied []*net.IPNet
	for _, d := range denylist {
		d = strings.TrimSpace(d)
		if strings.Contains(d, "/") {
			if _, n, err := net.ParseCIDR(d); err == nil {
				denied = append(denied, n)
			}
		} else if ip := net.ParseIP(d); ip != nil {
			denied = append(denied, &net.IPNet{IP: ip, Mask: net.CIDRMask(len(ip)*8, len(ip)*8)})
		}
	}
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		if strings.Contains(t, "/") || net.ParseIP(t) != nil {
			base := t
			if ip := net.ParseIP(t); ip != nil {
				if !denies(denied, ip) {
					out = append(out, base)
				}
				continue
			}
			ip, ipnet, err := net.ParseCIDR(t)
			if err != nil {
				continue
			}
			if denies(denied, ip) || fullyCovered(denied, ipnet) {
				continue
			}
			out = append(out, t)
			continue
		}
		out = append(out, t)
	}
	return out
}

func denies(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func fullyCovered(nets []*net.IPNet, ipnet *net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ipnet.IP) && ones(n.Mask) >= ones(ipnet.Mask) {
			return true
		}
	}
	return false
}

func ones(m net.IPMask) int {
	n := 0
	for _, b := range m {
		for b > 0 {
			n += int(b & 1)
			b >>= 1
		}
	}
	return n
}

func isPublic(ip net.IP) bool {
	if ip == nil {
		return true
	}
	for _, p := range privateV4 {
		if _, n, _ := net.ParseCIDR(p); n.Contains(ip) {
			return false
		}
	}
	for _, p := range privateV6 {
		if _, n, _ := net.ParseCIDR(p); n.Contains(ip) {
			return false
		}
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}

func allPrivate(targets []string) bool {
	for _, t := range targets {
		if strings.Contains(t, "/") {
			ip, _, err := net.ParseCIDR(t)
			if err != nil || isPublic(ip) {
				return false
			}
			continue
		}
		if ip := net.ParseIP(t); ip != nil {
			if isPublic(ip) {
				return false
			}
			continue
		}
		if strings.Contains(t, "-") {
			lo, _, err := parseRange(t)
			if err != nil || isPublic(lo) {
				return false
			}
			continue
		}
		// hostname: treat as non-private (unknown resolution).
		return false
	}
	return true
}

// parseRange parses "192.168.1.10-192.168.1.20" or "192.168.1.10-20".
func parseRange(r string) (net.IP, net.IP, error) {
	parts := strings.SplitN(r, "-", 2)
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("invalid IP range %q (want start-end)", r)
	}
	lo := net.ParseIP(strings.TrimSpace(parts[0]))
	if lo == nil {
		return nil, nil, fmt.Errorf("invalid IP range %q: bad start", r)
	}
	hiStr := strings.TrimSpace(parts[1])
	if !strings.Contains(hiStr, ".") && strings.Contains(parts[0], ".") {
		// "10.0.0.1-20" shorthand
		base := lo.To4()
		n, err := strconv.Atoi(hiStr)
		if err != nil || n < 0 || n > 255 {
			return nil, nil, fmt.Errorf("invalid IP range %q: bad end", r)
		}
		end := make(net.IP, len(base))
		copy(end, base)
		end[3] = byte(n)
		return lo, end, nil
	}
	hi := net.ParseIP(hiStr)
	if hi == nil {
		return nil, nil, fmt.Errorf("invalid IP range %q: bad end", r)
	}
	return lo, hi, nil
}

// isSuspiciousHostname rejects strings that should never reach a resolver
// or a command line (SSRF/injection defense).
func isSuspiciousHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return true
	}
	l := strings.ToLower(h)
	for _, bad := range []string{"localhost", "127.", "0.0.0.0", "[::1]", "metadata.google", "169.254.169.254", "file:", "gopher:", "unix:", "$(", "`", ";", "|", "&", "\n", "\r", ".."} {
		if strings.Contains(l, bad) {
			return true
		}
	}
	if net.ParseIP(h) != nil {
		return false
	}
	for _, label := range strings.Split(strings.Trim(h, "."), ".") {
		if label == "" || len(label) > 63 {
			return true
		}
		for _, r := range label {
			ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
			if !ok {
				return true
			}
		}
	}
	return false
}

// ExpandCIDR lists addresses in a small CIDR (used by the simulated engine
// and tests; real engines receive the CIDR directly).
func ExpandCIDR(cidr string, limit int) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	var out []string
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); inc(cur) {
		out = append(out, cur.String())
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// ipRangeSize counts addresses between two IPs (bounded, 64-bit safe).
func ipRangeSize(lo, hi net.IP) int {
	l, h := lo.To16(), hi.To16()
	diff := 0
	for i := 0; i < 16; i++ {
		diff = diff*256 + int(h[i]) - int(l[i])
		if diff > 1<<30 {
			return 1 << 30
		}
		if diff < 0 {
			return -1
		}
	}
	return diff
}

// rangeToCIDRs decomposes an arbitrary inclusive IP range into the minimal
// list of CIDR blocks covering it (the standard "range to CIDR" split).
// nmap's argv accepts CIDRs and octet shorthand but not "ip-ip" pairs, and
// canonical CIDRs keep scope storage and denylist math uniform. IPv4 and
// IPv6 ranges are both handled; a full-space range collapses to one block.
func rangeToCIDRs(lo, hi net.IP) []string {
	if lo == nil || hi == nil {
		return nil
	}
	v4 := lo.To4() != nil && hi.To4() != nil
	l := append([]byte(nil), lo.To16()...)
	h := append([]byte(nil), hi.To16()...)
	var out []string
	for bytes.Compare(l, h) <= 0 {
		hostBits := 0
		for hostBits < 128 &&
			lowBitsZero(l, hostBits+1) &&
			bytes.Compare(orLowBits(l, hostBits+1), h) <= 0 {
			hostBits++
		}
		prefix := 128 - hostBits
		ip := l
		if v4 {
			ip = l[12:]
			prefix -= 96
		}
		out = append(out, net.IP(ip).String()+"/"+strconv.Itoa(prefix))
		if hostBits >= 128 {
			break
		}
		l = addPow2(l, hostBits)
	}
	return out
}

// lowBitsZero reports whether the lowest n bits of the 16-byte big-endian
// address are all zero (block alignment check).
func lowBitsZero(b []byte, n int) bool {
	if n <= 0 {
		return true
	}
	if n > 128 {
		return false
	}
	full := n / 8
	for i := 16 - full; i < 16; i++ {
		if b[i] != 0 {
			return false
		}
	}
	if rem := n % 8; rem > 0 {
		if mask := byte(1<<uint(rem)) - 1; b[16-full-1]&mask != 0 {
			return false
		}
	}
	return true
}

// orLowBits returns b with its lowest n bits set - the last address of the
// aligned block starting at b (b must be aligned for n bits).
func orLowBits(b []byte, n int) []byte {
	out := append([]byte(nil), b...)
	if n <= 0 {
		return out
	}
	if n >= 128 {
		for i := range out {
			out[i] = 0xff
		}
		return out
	}
	full := n / 8
	for i := 16 - full; i < 16; i++ {
		out[i] = 0xff
	}
	if rem := n % 8; rem > 0 {
		out[16-full-1] |= byte(1<<uint(rem)) - 1
	}
	return out
}

// addPow2 returns b + 2^n as a real ripple-carry add. Callers usually pass
// block-aligned addresses (low n bits zero, so the add cannot carry below
// bit n), but n = 0 on an odd address must still increment correctly - the
// naive "set bit n" shortcut looped forever there (l|1 == l for odd l).
func addPow2(b []byte, n int) []byte {
	out := append([]byte(nil), b...)
	if n >= 128 {
		for i := range out {
			out[i] = 0
		}
		return out
	}
	idx := 15 - n/8
	carry := byte(1) << uint(n%8)
	for i := idx; i >= 0 && carry > 0; i-- {
		sum := int(out[i]) + int(carry)
		out[i] = byte(sum)
		carry = byte(sum >> 8)
	}
	return out
}

func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
