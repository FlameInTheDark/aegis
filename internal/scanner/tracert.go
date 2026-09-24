package scanner

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// tracertTraceroute is the Windows fallback of Engine.Traceroute: tracert.exe
// ships with every Windows install and needs no elevation — it sends ICMP
// echo requests with increasing TTLs via the standard API. nmap's raw-packet
// traceroute, by contrast, requires Npcap AND an elevated process on Windows;
// without them every ladder attempt fails and the scan used to degrade to a
// bare gateway guess even though a real route was one `tracert` away.
//
// Output is plain text (always localized on Windows!) — parsed by
// parseTracert, which keys on hop indices and IPv4 literals so it works
// regardless of the system language.
//
// Returns ok=false on non-Windows platforms, when the binary is unavailable
// or produced no usable hops — the caller then falls through to the next
// fallback. Unresponsive hops ("  2     *        *        *     Request
// timed out.") carry no address and are skipped, NOT treated as route
// failure: the returned path simply has TTL gaps.
func tracertTraceroute(ctx context.Context, target string, limits Limits) (Trace, bool) {
	if runtime.GOOS != "windows" {
		return Trace{}, false
	}
	bin := tracertBin()
	if bin == "" {
		return Trace{}, false
	}
	host := strings.Split(target, "/")[0]
	if !isIPv4(host) {
		return Trace{}, false // tracert -6 output differs; nmap attempts cover v6
	}
	limits.MaxRuntime = 60 * time.Second
	// -d: no reverse DNS per hop (fast, and keeps output parseable),
	// -4: IPv4, -h: bounded depth (LAN paths are 1-3 hops; 8 leaves room
	// for small routed networks), -w: per-probe reply timeout in ms.
	// Worst case per host: 8 hops x 3 probes x 400ms = ~10s, far inside
	// MaxRuntime; healthy LAN replies arrive in single-digit ms.
	stdout, _, code, err := run(ctx, limits, []string{bin, "-d", "-4", "-h", "8", "-w", "400", host})
	if err != nil || code != 0 {
		return Trace{}, false
	}
	hops := parseTracert(stdout, host)
	if len(hops) == 0 {
		return Trace{}, false
	}
	return Trace{Hops: hops, Method: "tracert", Raw: string(stdout)}, true
}

// tracertBin resolves tracert.exe: AEGIS_SCANNER_TRACERT_PATH override
// first, then PATH (C:\Windows\System32 is always on it). Empty means
// "unavailable" — the fallback is skipped silently, matching the engine's
// best-effort contract.
func tracertBin() string {
	if p := strings.TrimSpace(os.Getenv("AEGIS_SCANNER_TRACERT_PATH")); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		return "" // explicit override that doesn't exist: don't guess
	}
	if p, err := exec.LookPath("tracert.exe"); err == nil {
		return p
	}
	if p, err := exec.LookPath("tracert"); err == nil {
		return p
	}
	return ""
}

var (
	// "  1     1 ms     1 ms     1 ms  192.168.1.1" — responding hop.
	// "  2     *        *        *     Request timed out." — no address.
	// Hop lines always start with the integer TTL; the header
	// ("Tracing route to ...") and summary lines never do.
	reTracertHop = regexp.MustCompile(`^\s*(\d+)\s+`)
	// "<1 ms" and "1 ms" replies; the "<1" value is skipped (parse fails),
	// which is fine — RTT is decoration, the path is the product.
	reTracertRTT = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)\s*ms`)
	// IPv4 literal inside the line. With -d there is no hostname, so the
	// address is the only token worth extracting.
	reTracertIPv4 = regexp.MustCompile(`\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b`)
)

// parseTracert parses `tracert -d -4 <target>` text output. Locale-proof by
// construction: Windows localizes the wording ("Request timed out" becomes
// e.g. "Zeitüberschreitung der Anforderung."), but hop indices are plain
// integers and addresses are locale-independent — lines without any IPv4
// literal are unresponsive hops and are skipped.
func parseTracert(data []byte, target string) []Hop {
	var out []Hop
	seen := map[int]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		m := reTracertHop.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ttl, err := strconv.Atoi(m[1])
		if err != nil || seen[ttl] {
			continue
		}
		ipm := reTracertIPv4.FindStringSubmatch(line)
		if ipm == nil {
			continue // localized timeout / address-less line: TTL gap
		}
		ip := ipm[1]
		if !validIPv4(ip) {
			continue
		}
		hop := Hop{TTL: ttl, IP: ip}
		if rm := reTracertRTT.FindStringSubmatch(line); rm != nil {
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
	// tracert stops on its own once the target answers; when the reply
	// budget cut the trace short the partial path is returned as-is —
	// blocked probes must not be reported as "no route" nor invent a
	// destination.
	return out
}
