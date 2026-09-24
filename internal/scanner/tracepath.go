package scanner

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// tracepathTraceroute is the last resort of Engine.Traceroute: the standalone
// tracepath binary (iputils). It probes with UDP and needs no raw sockets,
// reports PMTU along the path, and keeps going where ICMP-echo traceroutes
// die (blocked echo, filtered time-exceeded on the probe itself). Output is
// plain text, parsed by parseTracepath.
//
// Returns ok=false when the binary is unavailable or produced no usable
// hops — the caller then falls through to its normal empty/error handling.
// Unresponsive hops ("2:  no reply") are skipped, NOT treated as route
// failure: the returned path simply has TTL gaps.
func tracepathTraceroute(ctx context.Context, target string, limits Limits) (Trace, bool) {
	bin := tracepathBin()
	if bin == "" {
		return Trace{}, false
	}
	// tracepath only traces the host itself; strip any CIDR suffix the way
	// the rest of the engine does before validating.
	host := strings.Split(target, "/")[0]
	if !isIPv4(host) {
		return Trace{}, false // iputils tracepath(6) output differs; nmap attempts cover v6
	}
	limits.MaxRuntime = 60 * time.Second
	stdout, _, code, err := run(ctx, limits, []string{bin, "-n", host})
	if err != nil || code != 0 {
		return Trace{}, false
	}
	hops := parseTracepath(stdout, host)
	if len(hops) == 0 {
		return Trace{}, false
	}
	return Trace{Hops: hops, Method: "tracepath", Raw: string(stdout)}, true
}

// tracepathBin resolves the tracepath binary: AEGIS_SCANNER_TRACEPATH_PATH
// override first, then PATH. Empty means "not shipped in this image" — the
// fallback is skipped silently, matching the engine's best-effort contract.
func tracepathBin() string {
	if p := strings.TrimSpace(os.Getenv("AEGIS_SCANNER_TRACEPATH_PATH")); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		return "" // explicit override that doesn't exist: don't guess
	}
	if p, err := exec.LookPath("tracepath"); err == nil {
		return p
	}
	return ""
}

var (
	// " 1:  gateway (192.168.65.1)             0.296ms" — hop with hostname+IP.
	// " 3:  1.1.1.1                           12.345ms reached" — bare IP.
	// " 2:  no reply" — unresponsive TTL, skipped (NOT a route failure).
	reTraceHop = regexp.MustCompile(`^\s*(\d+)(\?)?:\s+(.*)$`)
	reTraceRTT = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)ms`)
	// IPv4 with word boundaries; hostname (or bare IP) precedes it in parens.
	reTraceIPv4 = regexp.MustCompile(`\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b`)
	reHostname  = regexp.MustCompile(`^([^\s(]+)\s*\(`)
)

// parseTracepath parses `tracepath -n <target>` text output:
//
//	1?: [LOCALHOST]                      pmtu 1500
//	1:  gateway (192.168.65.1)             0.296ms
//	2:  no reply
//	3:  1.1.1.1                           12.345ms reached
//	    Resume: pmtu 1500
//
// iputils re-prints a TTL when a probe was retransmitted; the first line
// carrying an IP for that TTL wins. "reached" marks the final hop: when the
// target is reached the parser appends it exactly like the nmap parser, so
// downstream shapes stay identical. When the path is cut short ("no reply"
// to the end), the partial path is returned as-is — blocked probes must not
// be reported as "no route" nor invent a destination.
func parseTracepath(data []byte, target string) []Hop {
	var out []Hop
	seen := map[int]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		m := reTraceHop.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ttl, err := strconv.Atoi(m[1])
		if err != nil || seen[ttl] {
			continue
		}
		rest := m[3]
		ipm := reTraceIPv4.FindStringSubmatch(rest)
		if ipm == nil {
			continue // "no reply" / PMTU-only lines: TTL gap, keep going
		}
		ip := ipm[1]
		if !validIPv4(ip) {
			continue
		}
		hop := Hop{TTL: ttl, IP: ip}
		if hm := reHostname.FindStringSubmatch(rest); hm != nil && hm[1] != ip {
			hop.Hostname = hm[1]
		}
		if rm := reTraceRTT.FindStringSubmatch(rest); rm != nil {
			if ms, perr := strconv.ParseFloat(rm[1], 64); perr == nil {
				hop.RTTms = ms
			}
		}
		seen[ttl] = true
		out = append(out, hop)
	}
	if len(out) == 0 {
		return nil
	}
	last := out[len(out)-1]
	if strings.Contains(string(data), "reached") && last.IP != target {
		out = append(out, Hop{TTL: last.TTL + 1, IP: target})
	}
	return out
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return validIPv4(s)
}

func validIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) > 3 {
			return false
		}
		n := 0
		if p == "" {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
			n = n*10 + int(r-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}
