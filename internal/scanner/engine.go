// Package scanner implements external scanning engines behind explicit Go
// adapters: nmap, zgrab2 and a built-in simulated engine used
// for demos/tests. All external execution uses exec.CommandContext with
// argument arrays — never a shell — and enforces timeouts, output caps and
// target validation.
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// Limits bounds every engine run.
type Limits struct {
	MaxRuntime    time.Duration
	MaxStdout     int64 // bytes
	MaxStderr     int64
	MaxTargets    int
	MaxPacketRate int
}

// DefaultLimits is the conservative baseline.
func DefaultLimits() Limits {
	return Limits{MaxRuntime: 30 * time.Minute, MaxStdout: 64 << 20, MaxStderr: 1 << 20, MaxTargets: 8192, MaxPacketRate: 300}
}

// Engine is the common interface all scan engines implement.
type Engine interface {
	Name() string
	// DiscoverHosts returns alive hosts in the target set.
	DiscoverHosts(ctx context.Context, targets []string, cfg *domain.ScanConfig, limits Limits) ([]HostResult, error)
	// ScanPorts returns open ports for one target.
	ScanPorts(ctx context.Context, target string, ports []int, cfg *domain.ScanConfig, limits Limits) ([]PortResult, error)
	// FingerprintService enriches one open port.
	FingerprintService(ctx context.Context, target string, port int, proto string, cfg *domain.ScanConfig, limits Limits) (*ServiceResult, error)
	// FingerprintOS guesses the OS of a target.
	FingerprintOS(ctx context.Context, target string, cfg *domain.ScanConfig, limits Limits) (*OSResult, error)
	// FingerprintServicesLite enriches several open ports in ONE batched,
	// light (-sV --version-light) run. Engines that only support per-port
	// probing may implement it as a loop; it exists so "fingerprint"-style
	// profiles can harvest service-table OS hints without the cost of
	// full per-port version detection.
	FingerprintServicesLite(ctx context.Context, target string, ports []int, cfg *domain.ScanConfig, limits Limits) ([]ServiceResult, error)
	// Traceroute returns the network path from the scanner to the target.
	// The last hop is the target itself. Best effort: engines may return an
	// empty path when tracing is impossible (filtered ICMP, no privileges).
	// The Trace carries the probe family and the raw engine output alongside
	// the parsed hops (see Trace).
	Traceroute(ctx context.Context, target string, cfg *domain.ScanConfig, limits Limits) (Trace, error)
	// Version reports the engine binary version for audit logs.
	Version(ctx context.Context) (string, error)
}

// HostResult is one live host.
type HostResult struct {
	IP         string    `json:"ip"`
	Hostname   string    `json:"hostname,omitempty"`
	MAC        string    `json:"mac,omitempty"`
	MACVendor  string    `json:"mac_vendor,omitempty"`
	OS         *OSResult `json:"os,omitempty"`
	Device     string    `json:"device_type,omitempty"`
	Confidence float64   `json:"confidence"`
}

// PortResult is one open port.
type PortResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service,omitempty"`
	State    string `json:"state"`
}

// ServiceResult is one fingerprinted service. CPE keeps the first CPE for
// compatibility; CPEs carries every CPE nmap attributed to the service —
// nmap appends the host OS CPE ("cpe:/o:linux:linux_kernel") after the
// application CPE, which is the only OS signal on hosts whose -O probes are
// filtered (typical for container-born scans).
type ServiceResult struct {
	Port       int             `json:"port"`
	Protocol   string          `json:"protocol"`
	Name       string          `json:"name,omitempty"`
	Product    string          `json:"product,omitempty"`
	Vendor     string          `json:"vendor,omitempty"`
	Version    string          `json:"version,omitempty"`
	CPE        string          `json:"cpe,omitempty"`
	CPEs       []string        `json:"cpes,omitempty"`
	Banner     string          `json:"banner,omitempty"`
	OSType     string          `json:"os_type,omitempty"` // nmap service table hint (linux, windows, ios, ...)
	Confidence float64         `json:"confidence"`
	TLS        json.RawMessage `json:"tls,omitempty"`
	HTTP       json.RawMessage `json:"http,omitempty"`
}

// OSResult is one OS fingerprint; Device carries the device-type
// classification (router/workstation/phone/iot/...) when the engine could
// determine it — empty means "no claim", the asset stays unknown.
type OSResult struct {
	Family     string  `json:"family"`
	Name       string  `json:"name"`
	Version    string  `json:"version"`
	Device     string  `json:"device_type,omitempty"`
	Confidence float64 `json:"confidence"`
	// Link-layer details nmap reports in the address records of an -O run;
	// empty when the probes never touched L2 (unprivileged or remote hop).
	MAC       string `json:"mac,omitempty"`
	MACVendor string `json:"mac_vendor,omitempty"`
}

// Hop is one router on the traced path from the scanner to a target.
type Hop struct {
	TTL      int     `json:"ttl"`
	IP       string  `json:"ip"`
	Hostname string  `json:"hostname,omitempty"`
	RTTms    float64 `json:"rtt_ms,omitempty"`
}

// Trace is the full result of one traceroute: the parsed hops, the probe
// family that produced them (nmap ladder kinds, tracert, tracepath,
// simulated) and the RAW engine output (nmap XML / tracert text). The raw
// output is persisted with the parsed path so operators can audit what the
// scanner actually observed instead of trusting the parse blindly.
type Trace struct {
	Hops   []Hop
	Method string // tcp-syn | udp | icmp | tcp-connect | tracert | tracepath | simulated
	Raw    string
}

// ---------------------------------------------------------------------------
// Process execution plumbing (shared by all external engines)

// RunHooks lets the scan pipeline tee raw engine output into the job log
// while the normal bounded capture still collects it for parsing.
type RunHooks struct {
	// OnCommand fires once per engine invocation with the full argv.
	OnCommand func(argv []string)
	// OnStderrLine fires for every complete stderr line the engine prints.
	OnStderrLine func(line string)
}

// lineSplitter wraps the bounded stderr capture and forwards complete
// lines to the hook. Partial trailing output is flushed on Close.
type lineSplitter struct {
	next io.Writer
	hook func(line string)
	buf  []byte
}

func (l *lineSplitter) Write(p []byte) (int, error) {
	if l.next != nil {
		if _, err := l.next.Write(p); err != nil {
			return 0, err
		}
	}
	if l.hook == nil {
		return len(p), nil
	}
	l.buf = append(l.buf, p...)
	for {
		i := bytes.IndexByte(l.buf, '\n')
		if i < 0 {
			// Bound the pending buffer: a pathological engine printing one
			// endless line must not grow memory without limit.
			if len(l.buf) > 64<<10 {
				l.hook(string(l.buf[:64<<10]) + " …[truncated]")
				l.buf = l.buf[:0]
			}
			break
		}
		line := l.buf[:i]
		l.buf = l.buf[i+1:]
		if len(line) > 0 {
			l.hook(string(line))
		}
	}
	return len(p), nil
}

func (l *lineSplitter) Close() {
	if l.hook != nil && len(l.buf) > 0 {
		l.hook(string(l.buf))
	}
	l.buf = nil
}

// cappedWriter is an io.Writer that silently drops output beyond a cap.
type cappedWriter struct {
	buf bytes.Buffer
	max int64
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if int64(c.buf.Len())+int64(len(p)) > c.max {
		room := int(c.max) - c.buf.Len()
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return c.buf.Write(p)
}

// withExtra appends a preset's validated extra nmap arguments. nmap accepts
// options anywhere in argv, so appending keeps every call site one-liner.
// The slice is allowlist-checked at preset create/update time; the engine
// never sees raw user strings.
func withExtra(cfg *domain.ScanConfig, argv []string) []string {
	if cfg == nil || len(cfg.ExtraArgs) == 0 {
		return argv
	}
	return append(argv, cfg.ExtraArgs...)
}

// run executes a command safely: no shell, arg arrays, hard timeout,
// bounded stdout/stderr, stderr separated. Optional hooks tee the argv and
// stderr lines to the caller (job log streaming) without changing capture.
func run(ctx context.Context, limits Limits, argv []string, hooks ...RunHooks) (stdout, stderr []byte, code int, err error) {
	if len(argv) == 0 {
		return nil, nil, -1, fmt.Errorf("empty argv")
	}
	var h RunHooks
	if len(hooks) > 0 {
		h = hooks[0]
	}
	if h.OnCommand != nil {
		h.OnCommand(argv)
	}
	ctx, cancel := context.WithTimeout(ctx, limits.MaxRuntime)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- argv built from typed config, validated targets
	var outW, errW cappedWriter
	outW.max, errW.max = limits.MaxStdout, limits.MaxStderr
	cmd.Stdout = &outW
	cmd.Stderr = &errW
	if h.OnStderrLine != nil {
		ls := &lineSplitter{next: &errW, hook: h.OnStderrLine}
		defer ls.Close()
		cmd.Stderr = ls
	}
	err = cmd.Run()
	stdout = outW.buf.Bytes()
	stderr = errW.buf.Bytes()
	if ctx.Err() == context.DeadlineExceeded {
		return stdout, stderr, -1, fmt.Errorf("%s exceeded %s runtime limit", argv[0], limits.MaxRuntime)
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return stdout, stderr, ee.ExitCode(), nil
		}
		return stdout, stderr, -1, err
	}
	return stdout, stderr, 0, nil
}

// validateTarget refuses anything that could escape typed config.
func validateTarget(t string) error {
	t = strings.TrimSpace(t)
	if t == "" || len(t) > 256 {
		return fmt.Errorf("invalid target length")
	}
	for _, r := range t {
		bad := !('0' <= r && r <= '9') && !('a' <= r && r <= 'z') && !('A' <= r && r <= 'Z') &&
			r != '.' && r != '-' && r != '/' && r != ':' && r != ',' && r != '_' && r != '[' && r != ']'
		if bad {
			return fmt.Errorf("invalid character %q in target", string(r))
		}
	}
	for _, bad := range []string{"--", ";", "$(", "`", "\n"} {
		if strings.Contains(t, bad) && !strings.HasPrefix(t, "--") {
			return fmt.Errorf("target contains forbidden sequence %q", bad)
		}
	}
	return nil
}

// portListArg renders a port spec for nmap ("80,443,1000-2000"). Contiguous
// runs are compressed into ranges so a 1..1000 request becomes "1-1000"
// instead of a thousand comma-separated items.
func portListArg(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	var sorted []int
	seen := map[int]bool{}
	for _, p := range ports {
		if p > 0 && p < 65536 && !seen[p] {
			sorted = append(sorted, p)
			seen[p] = true
		}
	}
	if len(sorted) == 0 {
		return ""
	}
	sort.Ints(sorted)
	var parts []string
	start, prev := sorted[0], sorted[0]
	for _, p := range sorted[1:] {
		if p == prev+1 {
			prev = p
			continue
		}
		parts = append(parts, rangeSpec(start, prev))
		start, prev = p, p
	}
	parts = append(parts, rangeSpec(start, prev))
	return strings.Join(parts, ",")
}

func rangeSpec(start, end int) string {
	if start == end {
		return fmt.Sprint(start)
	}
	return fmt.Sprintf("%d-%d", start, end)
}

// portSpecArgs decides how nmap should select ports. Priority:
//   - explicit list in cfg.TCPPorts or the ports parameter -> -p spec
//   - full range (cfg.FullTCPPorts)                        -> -p-
//   - top-N table (cfg.TopTCPPorts)                        -> --top-ports N
//
// Using nmap's own top-ports frequency table (instead of "1..N") matters:
// the old behavior scanned only low ports and missed MySQL 3306, RDP 3389,
// Postgres 5432, Redis 6379, HTTP-alt 8080 and every other high port.
func portSpecArgs(ports []int, cfg *domain.ScanConfig) []string {
	if len(ports) > 0 {
		if spec := portListArg(ports); spec != "" {
			return []string{"-p", spec}
		}
	}
	if cfg == nil {
		return []string{"--top-ports", "100"}
	}
	if cfg.FullTCPPorts {
		return []string{"-p-"}
	}
	if cfg.TopTCPPorts > 0 {
		return []string{"--top-ports", fmt.Sprint(minInt(cfg.TopTCPPorts, 65535))}
	}
	return []string{"--top-ports", "100"}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// Nmap adapter

// NmapEngine wraps the nmap binary. Default NSE category is "safe" only —
// never "vuln" or "exploit" without an administrative, elevated profile.
type NmapEngine struct {
	BinPath string
	// hooks tee raw engine diagnostics into the job log. Set once at
	// startup (scanexec sets per-scan emitters through the indirection the
	// hooks close over); the single-scan-per-executor invariant makes a
	// mutex unnecessary.
	hooks RunHooks
}

// SetOutputHooks installs the argv/stderr tee (scanexec.EngineHooker).
func (n *NmapEngine) SetOutputHooks(onCommand func(argv []string), onStderr func(line string)) {
	n.hooks = RunHooks{OnCommand: onCommand, OnStderrLine: onStderr}
}

func (n *NmapEngine) Name() string { return "nmap" }

// Version returns the nmap version string.
func (n *NmapEngine) Version(ctx context.Context) (string, error) {
	limits := DefaultLimits()
	limits.MaxRuntime = 10 * time.Second
	stdout, _, _, err := run(ctx, limits, []string{n.BinPath, "--version"})
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(string(stdout), "\n")
	return strings.TrimSpace(line), nil
}

// DiscoverHosts performs ping/TCP-SYN host discovery.
func (n *NmapEngine) DiscoverHosts(ctx context.Context, targets []string, cfg *domain.ScanConfig, limits Limits) ([]HostResult, error) {
	if len(targets) == 0 || len(targets) > limits.MaxTargets {
		return nil, fmt.Errorf("target count out of bounds: %d", len(targets))
	}
	for _, t := range targets {
		if err := validateTarget(t); err != nil {
			return nil, fmt.Errorf("target rejected: %w", err)
		}
	}
	argv := []string{n.BinPath, "-sn", "-PE", "-PP", "-PS21-23,80,443,445,3389",
		"--max-rate", fmt.Sprint(clampInt(cfgMaxRate(cfg), 1, limits.MaxPacketRate)),
		"--host-timeout", fmt.Sprintf("%ds", int(phaseTimeout(cfg, 60*time.Second).Seconds())),
		"-oX", "-", // XML output parsed below (XML only mode; no NSE at this stage)
	}
	argv = append(argv, targets...)
	argv = withExtra(cfg, argv)
	stdout, stderr, code, err := run(ctx, limits, argv, n.hooks)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("nmap host discovery exit %d: %s", code, truncateStr(string(stderr), 512))
	}
	return parseNmapDiscovery(stdout)
}

// ScanPorts runs a TCP SYN scan plus -sV service detection when the
// profile allows. SYN scans need raw-packet privileges; when the
// process lacks them we transparently fall back to a TCP connect scan so
// unprivileged demo/container deployments still get results.
func (n *NmapEngine) ScanPorts(ctx context.Context, target string, ports []int, cfg *domain.ScanConfig, limits Limits) ([]PortResult, error) {
	if err := validateTarget(target); err != nil {
		return nil, err
	}
	// Port sweeps scale with the port count and the packet rate: a
	// 65535-port audit sweep at 500 pps needs minutes — a fixed 30s budget
	// made nmap abort ("timed out") long before the high ports were tried.
	rate := clampInt(cfgMaxRate(cfg), 1, limits.MaxPacketRate)
	count := portCountFor(ports, cfg)
	budget := time.Duration(count/rate*4+60) * time.Second
	if budget < 2*time.Minute {
		budget = 2 * time.Minute
	}
	if budget > 25*time.Minute {
		budget = 25 * time.Minute
	}
	hostTimeout := fmt.Sprintf("%ds", int(phaseTimeout(cfg, budget).Seconds()))
	argv := []string{n.BinPath, "-Pn", "-n", "-sS", "--open", "-oX", "-",
		"--max-rate", fmt.Sprint(rate),
		"--host-timeout", hostTimeout}
	argv = append(argv, portSpecArgs(ports, cfg)...)
	argv = append(argv, target)
	argv = withExtra(cfg, argv)
	stdout, stderr, code, err := run(ctx, limits, argv, n.hooks)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		// Privilege fallback: -sS requires CAP_NET_RAW / root.
		argvFb := append([]string{n.BinPath, "-Pn", "-n", "-sT", "--open", "-oX", "-",
			"--max-rate", fmt.Sprint(rate),
			"--host-timeout", hostTimeout}, portSpecArgs(ports, cfg)...)
		argvFb = append(argvFb, target)
		argvFb = withExtra(cfg, argvFb)
		stdout2, _, code2, err2 := run(ctx, limits, argvFb, n.hooks)
		if err2 == nil && code2 == 0 {
			return parseNmapPorts(stdout2)
		}
		return nil, fmt.Errorf("nmap port scan exit %d: %s", code, truncateStr(string(stderr), 512))
	}
	return parseNmapPorts(stdout)
}

// FingerprintService uses -sV with version intensity limited; safe NSE
// scripts only when the profile permits.
func (n *NmapEngine) FingerprintService(ctx context.Context, target string, port int, proto string, cfg *domain.ScanConfig, limits Limits) (*ServiceResult, error) {
	if err := validateTarget(target); err != nil {
		return nil, err
	}
	argv := []string{n.BinPath, "-sV", "--version-intensity", "5", "-Pn", "-n",
		"--host-timeout", fmt.Sprintf("%ds", int(phaseTimeout(cfg, 90*time.Second).Seconds())),
		"-p", fmt.Sprint(port), "-oX", "-",
	}
	if cfgSafeNSE(cfg) {
		argv = append(argv, "--script", "safe") // never "vuln"/"exploit" here
	}
	argv = withExtra(cfg, argv)
	argv = append(argv, target)
	stdout, stderr, code, err := run(ctx, limits, argv, n.hooks)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("nmap sV exit %d: %s", code, truncateStr(string(stderr), 512))
	}
	res, err := parseNmapService(stdout, port)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, nil
	}
	res.Protocol = proto
	return res, nil
}

// FingerprintServicesLite enriches several open ports in one batched
// `nmap -sV --version-light` run. --version-light (intensity 2) sends only
// the most-likely probes per port: a fraction of the packets and time of the
// per-port intensity-5 pass, but still enough to fill the service table's
// product/version/ostype/CPE fields — which is what the orchestrator turns
// into OS and software records on hosts -O cannot fingerprint.
func (n *NmapEngine) FingerprintServicesLite(ctx context.Context, target string, ports []int, cfg *domain.ScanConfig, limits Limits) ([]ServiceResult, error) {
	if err := validateTarget(target); err != nil {
		return nil, err
	}
	if len(ports) == 0 {
		return nil, nil
	}
	spec := portListArg(ports)
	if spec == "" {
		return nil, nil
	}
	argv := []string{n.BinPath, "-sV", "--version-light", "-Pn", "-n",
		"--host-timeout", fmt.Sprintf("%ds", int(phaseTimeout(cfg, 120*time.Second).Seconds())),
		"-p", spec, "-oX", "-", target}
	argv = withExtra(cfg, argv)
	stdout, stderr, code, err := run(ctx, limits, argv, n.hooks)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("nmap sV-lite exit %d: %s", code, truncateStr(string(stderr), 512))
	}
	return parseNmapServices(stdout), nil
}

// FingerprintOS uses OS detection with limited probes. OS detection needs
// raw sockets; on failure the caller falls back to per-service OS hints.
// The 5-minute budget is deliberate: -O first runs its own port scan (to find
// an open AND a closed port for the probes) plus dozens of probe rounds. A
// 30s --host-timeout aborted the host before a single probe round finished —
// nmap printed no <os> block at all, which read as "no OS data in the app".
// --osscan-guess additionally reports near matches instead of nothing when
// no exact fingerprint matches.
//
// The port selection is deliberately bounded and explicit (osPortArgs):
// nmap's implicit default (top 1000) misses open ports outside that table,
// and hosts whose only open ports are unknown to -O get no <os> block at all.
// --osscan-limit is intentionally NOT used: it skips every host that lacks an
// open AND closed TCP port, and behind NATs that swallow RSTs (Docker bridge,
// Docker Desktop) closed ports show as filtered — the check fails exactly
// where scans run, silently zeroing the whole phase.
func (n *NmapEngine) FingerprintOS(ctx context.Context, target string, cfg *domain.ScanConfig, limits Limits) (*OSResult, error) {
	if err := validateTarget(target); err != nil {
		return nil, err
	}
	argv := osScanArgs(n.BinPath, target, cfg, limits, phaseTimeout(cfg, 5*time.Minute))
	argv = withExtra(cfg, argv)
	stdout, stderr, code, err := run(ctx, limits, argv, n.hooks)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		// Say WHY when privileges are missing — "exit 1" alone sent people
		// hunting through profiles and budgets for hours.
		msg := truncateStr(string(stderr), 512)
		if strings.Contains(msg, "requires root privileges") || strings.Contains(msg, "requires privileged") {
			return nil, fmt.Errorf("nmap -O needs raw sockets (CAP_NET_RAW / root): %s", msg)
		}
		return nil, fmt.Errorf("nmap -O exit %d: %s", code, msg)
	}
	return parseNmapOS(stdout)
}

// osPortArgs bounds the port selection inside an -O run. -O performs its own
// port scan to find the open+closed pair it probes with; left implicit it
// scans nmap's default top-1000, which both wastes time on full audits and
// misses hosts whose open ports sit outside that table. Explicit specs:
//   - explicit port list                         -> -p spec (up to 1000 ports)
//   - top-N smaller than the default table       -> --top-ports N (covers every
//     port the ports phase could have found)
//   - full range / big top-N                     -> --top-ports 1000 (capped:
//     re-probing 65535 ports inside -O doubles the audit runtime for no gain)
func osPortArgs(cfg *domain.ScanConfig) []string {
	if cfg == nil {
		return []string{"--top-ports", "1000"}
	}
	if len(cfg.TCPPorts) > 0 {
		if spec := portListArg(cfg.TCPPorts); spec != "" && len(cfg.TCPPorts) <= 1000 {
			return []string{"-p", spec}
		}
		return []string{"--top-ports", "1000"}
	}
	if cfg.TopTCPPorts > 0 && cfg.TopTCPPorts < 1000 {
		return []string{"--top-ports", fmt.Sprint(cfg.TopTCPPorts)}
	}
	return []string{"--top-ports", "1000"}
}

func osScanArgs(bin, target string, cfg *domain.ScanConfig, limits Limits, budget time.Duration) []string {
	argv := []string{bin, "-O", "--osscan-guess", "-Pn", "-n",
		"--max-rate", fmt.Sprint(clampInt(cfgMaxRate(cfg), 1, limits.MaxPacketRate)),
		"--host-timeout", fmt.Sprintf("%ds", int(budget.Seconds())),
		"-oX", "-"}
	argv = append(argv, osPortArgs(cfg)...)
	return append(argv, target)
}

// Traceroute traces the path from the scanner to one target using nmap's
// built-in traceroute, then the tracepath binary when nmap cannot see a
// path at all. Probe strategy, most reliable first:
//
//  1. TCP SYN/ACK discovery probes (-PS/-PA) — TCP responses survive
//     stateful NAT (Docker Desktop's user-space proxy, corporate firewalls)
//     far better than ICMP; the target itself answers with RST/SYN-ACK.
//  2. UDP probes (-PU) — elicit ICMP port-unreachable from the target;
//     gets through when TCP probes are filtered and ICMP echo is blocked.
//  3. ICMP echo + timestamp probes — the classic default.
//  4. TCP connect traceroute (-sT) as a last nmap resort.
//  5. tracepath (UDP, unprivileged, MTU-aware) when the binary exists.
//
// A path is returned as soon as any attempt yields hops. Unresponsive hops
// are NOT errors: their TTLs simply stay absent from the returned slice, so
// callers can tell "partial path (some hops blocked)" (TTL gaps, final hop
// reached) from "no path at all" (empty result). Note: intermediate hops can
// only ever be seen via ICMP Time Exceeded messages; container NATs that
// swallow those (Docker Desktop/WSL2) show partial paths regardless of probe
// type — the orchestrator links the deepest reachable hop to the asset. See
// docs/DEVELOPMENT.md "Traceroute from containers".
func (n *NmapEngine) Traceroute(ctx context.Context, target string, cfg *domain.ScanConfig, limits Limits) (Trace, error) {
	if err := validateTarget(target); err != nil {
		return Trace{}, err
	}
	limits.MaxRuntime = 3 * time.Minute
	hostTimeout := fmt.Sprintf("%ds", int(phaseTimeout(cfg, 90*time.Second).Seconds()))
	var lastErr error
	for _, argv := range tracerouteLadder(n.BinPath, target, cfg, limits, hostTimeout) {
		argv = withExtra(cfg, argv)
		stdout, stderr, code, err := run(ctx, limits, argv, n.hooks)
		if err != nil {
			return Trace{}, err
		}
		if code == 0 {
			if hops, perr := parseNmapTraceroute(stdout, target); perr == nil && len(hops) > 0 {
				return Trace{Hops: hops, Method: probeKind(argv), Raw: string(stdout)}, nil
			}
		} else {
			lastErr = fmt.Errorf("nmap traceroute (%s) exit %d: %s", probeKind(argv), code, truncateStr(string(stderr), 512))
		}
	}
	// Native platform fallbacks, before giving up on a real route:
	// Windows tracert.exe ships everywhere and needs no elevation (ICMP
	// echo via the standard API) — nmap's raw-packet traceroute needs
	// Npcap AND an admin process, so unprivileged Windows scans used to
	// lose the whole path. Skipped silently off-Windows.
	if tr, ok := tracertTraceroute(ctx, target, limits); ok {
		return tr, nil
	}
	// Then the standalone tracepath binary (UDP-based, needs no
	// raw sockets, tolerates NATs better than ICMP). Skipped silently
	// when the image does not ship it (AEGIS_SCANNER_TRACEPATH_PATH or
	// PATH).
	if tr, ok := tracepathTraceroute(ctx, target, limits); ok {
		return tr, nil
	}
	if lastErr != nil {
		return Trace{}, lastErr
	}
	return Trace{}, nil
}

// tracerouteLadder builds the ordered nmap traceroute attempts (see
// Traceroute). Exposed for tests: the ordering is a contract — NAT-friendliest
// probe first, loudest last.
func tracerouteLadder(bin, target string, cfg *domain.ScanConfig, limits Limits, hostTimeout string) [][]string {
	rate := fmt.Sprint(clampInt(cfgMaxRate(cfg), 1, limits.MaxPacketRate))
	return [][]string{
		// 1. TCP SYN + ACK discovery probes (NAT-friendliest).
		{bin, "-sn", "-PE", "-PP",
			"-PS21-23,80,443,445,3389", "-PA80,443", "--traceroute", "-n",
			"--max-rate", rate, "--host-timeout", hostTimeout, "-oX", "-", target},
		// 2. UDP probes on ports that reliably answer ICMP
		//    port-unreachable (DNS, NTP, SNMP, IKE, IPsec-nat).
		{bin, "-sn", "-PU53,123,161,500,4500", "--traceroute", "-n",
			"--max-rate", rate, "--host-timeout", hostTimeout, "-oX", "-", target},
		// 3. ICMP echo probes (plain `nmap -sn --traceroute`).
		{bin, "-sn", "-PE", "-PP", "--traceroute", "-n",
			"--host-timeout", hostTimeout, "-oX", "-", target},
		// 4. TCP connect probes on likely-open ports. The final hop now
		//    answers with TCP RST instead of ICMP, which gets through
		//    NATs that drop even target-bound ICMP error translations.
		{bin, "-sT", "-Pn", "--traceroute", "-n", "--open",
			"-p", "80,443,3389,445,22", "--host-timeout", hostTimeout, "-oX", "-", target},
	}
}

// probeKind names the probe type of a ladder argv for log lines. Priority
// beats position: the SYN attempt also carries -PE, so -PS must win even
// though -PE appears first in the argv.
func probeKind(argv []string) string {
	priority := []string{"-PS", "-PU", "-sT", "-PE"}
	names := map[string]string{"-PS": "tcp-syn", "-PU": "udp", "-sT": "tcp-connect", "-PE": "icmp"}
	for _, want := range priority {
		for _, a := range argv {
			if strings.HasPrefix(a, want) {
				return names[want]
			}
		}
	}
	return "nmap"
}

func cfgMaxRate(cfg *domain.ScanConfig) int {
	if cfg != nil && cfg.MaxRate > 0 {
		return cfg.MaxRate
	}
	return 100
}

func cfgTimeoutSecs(cfg *domain.ScanConfig) int {
	if cfg != nil && cfg.TimeoutSecs > 0 {
		return cfg.TimeoutSecs
	}
	return 30
}

// phaseTimeout returns the --host-timeout for one scan phase. Phases have
// very different shapes: a -O run performs its own port scan plus dozens of
// probe rounds; a 65535-port SYN sweep at 500 pps needs minutes; a ping
// sweep finishes in seconds. One global 30s budget silently aborted the OS
// phase before nmap emitted any <os> data. cfg.TimeoutSecs, when explicitly
// set, acts as a floor — deployments can only extend a phase budget.
func phaseTimeout(cfg *domain.ScanConfig, def time.Duration) time.Duration {
	if cfg != nil && cfg.TimeoutSecs > 0 {
		if d := time.Duration(cfg.TimeoutSecs) * time.Second; d > def {
			return d
		}
	}
	return def
}

// portCountFor estimates how many ports a scan will probe, used to size the
// port-phase --host-timeout budget.
func portCountFor(ports []int, cfg *domain.ScanConfig) int {
	if len(ports) > 0 {
		return len(ports)
	}
	if cfg != nil {
		if cfg.FullTCPPorts {
			return 65535
		}
		if cfg.TopTCPPorts > 0 {
			return cfg.TopTCPPorts
		}
	}
	return 100
}

func cfgSafeNSE(cfg *domain.ScanConfig) bool {
	if cfg == nil {
		return false
	}
	def, ok := domain.Profiles[cfg.Profile]
	return ok && def.SafeNSE
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ---------------------------------------------------------------------------
// Simulated engine (demo mode / tests / air-gapped evaluation)

// SimulatedEngine produces deterministic synthetic results so the whole
// pipeline can run without touching a real network (clearly
// identified demo data; no arbitrary real networks in tests).
type SimulatedEngine struct{}

func (s *SimulatedEngine) Name() string                                { return "simulated" }
func (s *SimulatedEngine) Version(ctx context.Context) (string, error) { return "simulated-1.0", nil }

func (s *SimulatedEngine) DiscoverHosts(ctx context.Context, targets []string, cfg *domain.ScanConfig, limits Limits) ([]HostResult, error) {
	var out []HostResult
	for _, cidr := range targets {
		// First host is intentionally identical to the long-standing demo
		// workstation (IP suffix .11, Linux) so existing tests and demo
		// narratives stay stable; the extra hosts give the UI a realistic
		// mix of device types (phone / camera / printer) to display.
		out = append(out, HostResult{IP: pickIP(cidr, 1), Hostname: hostnameFor(cidr, 1), Device: "workstation", Confidence: 0.9})
		out = append(out,
			HostResult{IP: pickIP(cidr, 2), Hostname: hostnameFor(cidr, 2), Device: "mobile", Confidence: 0.85},
			HostResult{IP: pickIP(cidr, 3), Hostname: hostnameFor(cidr, 3), Device: "camera", Confidence: 0.8},
			HostResult{IP: pickIP(cidr, 4), Hostname: hostnameFor(cidr, 4), Device: "printer", Confidence: 0.85},
		)
		if len(out) >= 32 {
			break
		}
	}
	return out, nil
}

func (s *SimulatedEngine) ScanPorts(ctx context.Context, target string, ports []int, cfg *domain.ScanConfig, limits Limits) ([]PortResult, error) {
	// The simulated service set includes high ports deliberately: full and
	// top-1000 scans must discover them the same way a real scan would.
	// Port sets vary by device class (deterministic per last octet) so the
	// demo inventory looks like a real mixed network.
	workstation := []PortResult{
		{Port: 22, Protocol: "tcp", Service: "ssh", State: "open"},
		{Port: 80, Protocol: "tcp", Service: "http", State: "open"},
		{Port: 443, Protocol: "tcp", Service: "https", State: "open"},
		{Port: 3389, Protocol: "tcp", Service: "ms-wbt-server", State: "open"},
		{Port: 5432, Protocol: "tcp", Service: "postgresql", State: "open"},
		{Port: 8080, Protocol: "tcp", Service: "http-proxy", State: "open"},
		{Port: 9200, Protocol: "tcp", Service: "elasticsearch", State: "open"},
	}
	common := workstation
	switch lastOctet(target) {
	case 12: // phone
		common = []PortResult{
			{Port: 443, Protocol: "tcp", Service: "https", State: "open"},
			{Port: 8080, Protocol: "tcp", Service: "http-proxy", State: "open"},
		}
	case 13: // camera
		common = []PortResult{
			{Port: 80, Protocol: "tcp", Service: "http", State: "open"},
			{Port: 554, Protocol: "tcp", Service: "rtsp", State: "open"},
		}
	case 14: // printer
		common = []PortResult{
			{Port: 80, Protocol: "tcp", Service: "http", State: "open"},
			{Port: 631, Protocol: "tcp", Service: "ipp", State: "open"},
			{Port: 9100, Protocol: "tcp", Service: "jetdirect", State: "open"},
		}
	}
	if len(ports) == 0 {
		// Full/top-N scan: report everything (deterministic per target).
		return common, nil
	}
	var out []PortResult
	for _, want := range ports {
		for _, c := range common {
			if c.Port == want {
				out = append(out, c)
			}
		}
	}
	return out, nil
}

func (s *SimulatedEngine) FingerprintService(ctx context.Context, target string, port int, proto string, cfg *domain.ScanConfig, limits Limits) (*ServiceResult, error) {
	switch port {
	case 22:
		return &ServiceResult{Port: port, Protocol: "tcp", Name: "ssh", Product: "OpenSSH", Vendor: "OpenBSD", Version: "9.6", CPE: "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*", Banner: "SSH-2.0-OpenSSH_9.6p1", OSType: "linux", Confidence: 0.95}, nil
	case 80:
		return &ServiceResult{Port: port, Protocol: "tcp", Name: "http", Product: "nginx", Vendor: "nginx", Version: "1.24.0", CPE: "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*", Banner: "Server: nginx/1.24.0", OSType: "linux", Confidence: 0.93}, nil
	case 443:
		return &ServiceResult{Port: port, Protocol: "tcp", Name: "https", Product: "nginx", Vendor: "nginx", Version: "1.24.0", CPE: "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*", Banner: "Server: nginx/1.24.0", OSType: "linux", Confidence: 0.93}, nil
	case 3389:
		return &ServiceResult{Port: port, Protocol: "tcp", Name: "ms-wbt-server", Product: "Microsoft Terminal Services", Vendor: "Microsoft", Version: "10.0", CPE: "cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*", OSType: "windows", Confidence: 0.85}, nil
	case 5432:
		return &ServiceResult{Port: port, Protocol: "tcp", Name: "postgresql", Product: "PostgreSQL", Vendor: "PostgreSQL", Version: "15.4", CPE: "cpe:2.3:a:postgresql:postgresql:15.4:*:*:*:*:*:*:*", Banner: "PostgreSQL 15.4", OSType: "linux", Confidence: 0.9}, nil
	case 8080:
		return &ServiceResult{Port: port, Protocol: "tcp", Name: "http-proxy", Product: "Apache Tomcat", Vendor: "Apache", Version: "9.0.71", CPE: "cpe:2.3:a:apache:tomcat:9.0.71:*:*:*:*:*:*:*", Banner: "Apache-Coyote/1.1", OSType: "linux", Confidence: 0.85}, nil
	case 9200:
		return &ServiceResult{Port: port, Protocol: "tcp", Name: "elasticsearch", Product: "Elasticsearch", Vendor: "Elastic", Version: "7.17.9", CPE: "cpe:2.3:a:elastic:elasticsearch:7.17.9:*:*:*:*:*:*:*", Banner: "cluster_name: aegis-demo", OSType: "linux", Confidence: 0.85}, nil
	case 554:
		return &ServiceResult{Port: port, Protocol: "tcp", Name: "rtsp", Product: "IP Camera RTSP", Vendor: "GenericCam", Version: "2.1", CPE: "cpe:2.3:h:genericcam:ip_camera:2.1:*:*:*:*:*:*:*", Banner: "RTSP/1.0 200 OK", OSType: "embedded", Confidence: 0.8}, nil
	case 631:
		return &ServiceResult{Port: port, Protocol: "tcp", Name: "ipp", Product: "CUPS IPP", Vendor: "Apple", Version: "2.1", Banner: "ipp: USB Thermal Printer", OSType: "embedded", Confidence: 0.75}, nil
	case 9100:
		return &ServiceResult{Port: port, Protocol: "tcp", Name: "jetdirect", Product: "HP JetDirect", Vendor: "HP", Version: "L11", CPE: "cpe:2.3:h:hp:laserjet:L11:*:*:*:*:*:*:*", Banner: "JetDirect L11", OSType: "embedded", Confidence: 0.85}, nil
	default:
		return &ServiceResult{Port: port, Protocol: proto, Name: "unknown", Confidence: 0.3}, nil
	}
}

func (s *SimulatedEngine) FingerprintOS(ctx context.Context, target string, cfg *domain.ScanConfig, limits Limits) (*OSResult, error) {
	// Per-device fingerprints (deterministic by last octet) so the asset list
	// shows a realistic OS mix; the .11 workstation keeps the long-standing
	// Linux 6.1 demo fingerprint.
	switch lastOctet(target) {
	case 12:
		return &OSResult{Family: "android", Name: "Android", Version: "14", Device: "mobile", Confidence: 0.7}, nil
	case 13:
		return &OSResult{Family: "linux", Name: "BusyBox", Version: "1.36", Device: "camera", Confidence: 0.65}, nil
	case 14:
		return &OSResult{Family: "embedded", Name: "HP JetDirect", Version: "L11", Device: "printer", Confidence: 0.7}, nil
	default:
		return &OSResult{Family: "linux", Name: "Linux", Version: "6.1", Device: "workstation", Confidence: 0.6}, nil
	}
}

// FingerprintServicesLite loops the per-port simulated table (one batched
// call in the nmap engine; a fan-out here keeps the demo deterministic).
func (s *SimulatedEngine) FingerprintServicesLite(ctx context.Context, target string, ports []int, cfg *domain.ScanConfig, limits Limits) ([]ServiceResult, error) {
	var out []ServiceResult
	for _, p := range ports {
		svc, err := s.FingerprintService(ctx, target, p, "tcp", cfg, limits)
		if err != nil || svc == nil {
			continue
		}
		out = append(out, *svc)
	}
	return out, nil
}

// Traceroute synthesizes a deterministic two-hop path: the gateway (first
// usable address of the target's /24) and the target itself. This gives
// demo/air-gapped deployments a sensible topology without touching a network.
func (s *SimulatedEngine) Traceroute(ctx context.Context, target string, cfg *domain.ScanConfig, limits Limits) (Trace, error) {
	var out []Hop
	if gw := GatewayOf(target); gw != "" && gw != target {
		out = append(out, Hop{TTL: 1, IP: gw, RTTms: 1.2})
	}
	out = append(out, Hop{TTL: len(out) + 1, IP: target, RTTms: 4.5})
	return Trace{Hops: out, Method: "simulated"}, nil
}

// GatewayOf returns the first usable host address of the target's /24 for
// IPv4 inputs ("192.168.1.1" from "192.168.1.55"). Non-IPv4 returns "".
func GatewayOf(target string) string {
	base := strings.Split(strings.Split(target, "/")[0], ".")
	if len(base) != 4 {
		return ""
	}
	n := make([]int, 4)
	for i, p := range base {
		v := 0
		for _, r := range p {
			if r < '0' || r > '9' {
				return ""
			}
			v = v*10 + int(r-'0')
		}
		if v > 255 {
			return ""
		}
		n[i] = v
	}
	if n[3] == 1 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.1", n[0], n[1], n[2])
}

func pickIP(cidr string, i int) string {
	base := strings.Split(cidr, "/")[0]
	parts := strings.Split(base, ".")
	if len(parts) == 4 {
		parts[3] = fmt.Sprint(10 + i)
		base = strings.Join(parts, ".")
	}
	return base
}

// lastOctet returns the final IPv4 octet, or 0 for non-IPv4 inputs.
func lastOctet(target string) int {
	parts := strings.Split(strings.Split(target, "/")[0], ".")
	if len(parts) != 4 {
		return 0
	}
	n := 0
	for _, r := range parts[3] {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func hostnameFor(cidr string, i int) string {
	return "host-" + strings.ReplaceAll(strings.Split(cidr, "/")[0], ".", "-") + "-" + fmt.Sprint(10+i)
}
