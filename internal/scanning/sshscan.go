// Agent-less SSH host collection. Vuls' signature capability applied to aegis: connect to hosts
// over SSH (no agent installed), fingerprint the distro from
// /etc/os-release, enumerate installed packages with distro-native commands,
// and feed the same inventory + advisory-correlation pipeline the endpoint
// agents use.
//
// Only read-only, non-root commands are executed (vuls' "fast scan"
// posture): dpkg-query, rpm -qa, apk list and cat. Every command is a
// fixed string — no host-controlled input is ever interpolated.
package scanning

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/fingerprinting"
	"golang.org/x/crypto/ssh"
)

// SSHPackage is one installed package reported by a remote host.
type SSHPackage struct {
	Name    string
	Version string
}

// SSHHostConfig is one collection target.
type SSHHostConfig struct {
	Host string // IP or hostname (becomes the asset's primary IP identifier)
	Port int    // default 22
	User string // default from config
}

// SSHHostResult carries what one host yielded (or the error — collection is
// per-host isolated; one unreachable host never fails the scan).
type SSHHostResult struct {
	Host      SSHHostConfig
	OSFamily  string
	OSName    string
	OSVersion string
	OSOK      bool
	Packages  []SSHPackage
	Err       string
	// Commands logs every read-only command executed on the host, in
	// order, with outcome and output line count - the audit trail
	// behind "show what exactly being scanned over SSH".
	Commands   []domain.SSHCommandRun
	DurationMS int64
}

// --- command builders (fixed strings — see package doc) ---

const (
	dpkgQueryCmd = `dpkg-query -W -f='${binary:Package}|${db:Status-Abbrev}|${Version}\n' 2>/dev/null`
	rpmQueryCmd  = `rpm -qa --queryformat '%{NAME}|%{VERSION}-%{RELEASE}\n' 2>/dev/null`
	apkListCmd   = `apk list --installed 2>/dev/null`
	osReleaseCmd = `cat /etc/os-release 2>/dev/null`
	whichDpkgCmd = `command -v dpkg-query >/dev/null 2>&1 && echo dpkg`
	whichRpmCmd  = `command -v rpm >/dev/null 2>&1 && echo rpm`
	whichApkCmd  = `command -v apk >/dev/null 2>&1 && echo apk`
)

// --- parsers ---

// ParseDpkgQuery parses dpkg-query output lines
// "name:arch|status-abbrev|version". Only fully installed packages
// (status "ii") are returned; the :arch suffix is stripped from names.
func ParseDpkgQuery(stdout string) []SSHPackage {
	out := []SSHPackage{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			continue
		}
		name := parts[0]
		status := parts[1]
		ver := strings.TrimSpace(parts[2])
		if !strings.HasPrefix(status, "ii") || ver == "" {
			continue // not fully installed
		}
		if i := strings.IndexByte(name, ':'); i > 0 {
			name = name[:i] // strip :arch
		}
		out = append(out, SSHPackage{Name: name, Version: ver})
	}
	return out
}

// ParseRpmQA parses rpm -qa output lines "name|version-release".
func ParseRpmQA(stdout string) []SSHPackage {
	out := []SSHPackage{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			continue
		}
		out = append(out, SSHPackage{Name: parts[0], Version: parts[1]})
	}
	return out
}

// ParseApkList parses `apk list --installed` lines whose first token is
// "name-version-release ..." (vuls' split: name = all but the last two dash
// components, version = the last two joined).
func ParseApkList(stdout string) []SSHPackage {
	out := []SSHPackage{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Real `apk list` lines always carry the "arch {origin} (license)
		// [status]" metadata suffix; require it so garbage lines are
		// skipped instead of parsed as name-version pairs.
		if !strings.Contains(line, "{") || !strings.Contains(line, "[") {
			continue
		}
		pkgver := strings.Fields(line)[0]
		ss := strings.Split(pkgver, "-")
		if len(ss) < 3 {
			continue
		}
		name := strings.Join(ss[:len(ss)-2], "-")
		version := strings.Join(ss[len(ss)-2:], "-")
		if name == "" || version == "" {
			continue
		}
		out = append(out, SSHPackage{Name: name, Version: version})
	}
	return out
}

// ParseOSReleaseHost resolves os_family/os_name/os_version for the
// observation payload from /etc/os-release content.
func ParseOSReleaseHost(stdout string) (family, name, version string, ok bool) {
	fields := map[string]string{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		fields[strings.ToUpper(strings.TrimSpace(k))] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	seg, ok := fingerprinting.ParseOSRelease(stdout)
	if !ok {
		return "", "", "", false
	}
	pretty := fields["PRETTY_NAME"]
	if pretty == "" {
		pretty = seg.Family + " " + seg.Release
	}
	return seg.Family, pretty, fields["VERSION_ID"], true
}

// --- transport ---

// SSHRunner executes one command on one host. Implemented by SSHClient;
// faked in tests.
type SSHRunner interface {
	Run(ctx context.Context, host SSHHostConfig, cmd string) (string, error)
}

// SSHClient dials hosts over SSH with password or key auth and runs
// fixed command strings.
type SSHClient struct {
	User     string
	Password string
	KeyPEM   []byte
	// KeyPath is optional and exists only to make error messages
	// actionable (naming the configured file that was unusable).
	KeyPath string
	Timeout time.Duration
	// InsecureHostKey accepts any host key. Required unless a pinned key
	// is configured; deployments that care pin host keys.
	InsecureHostKey bool
	HostKeyPinned   string // "ssh-ed25519 AAAA..." style line (optional)
}

func (c *SSHClient) authMethods() ([]ssh.AuthMethod, error) {
	methods := []ssh.AuthMethod{}
	if len(c.KeyPEM) > 0 {
		signer, err := ssh.ParsePrivateKey(c.KeyPEM)
		if err != nil {
			// An unusable key must not take password auth down with it:
			// skip the key method when a password can take over (the
			// executor pre-flight already warns about the dropped key),
			// and fail with an actionable error only when the key is the
			// sole configured credential.
			if c.Password == "" {
				return nil, DescribeKeyError(c.KeyPath, err)
			}
		} else {
			methods = append(methods, ssh.PublicKeys(signer))
		}
	}
	if c.Password != "" {
		methods = append(methods, ssh.Password(c.Password))
		// Many sshd setups disable plain "password" but keep
		// keyboard-interactive (PAM): offer the password through both
		// so hardened hosts still accept login+password scanning.
		methods = append(methods, ssh.KeyboardInteractive(
			func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = c.Password
				}
				return answers, nil
			}))
	}
	return methods, nil
}

// DescribeKeyError turns a private-key parsing failure into an actionable
// error. The raw x/crypto messages name neither the file nor the usual
// causes: "ssh: no key found" almost always means the configured path
// points at something that is not a PEM private key (a *.pub public key,
// a PuTTY .ppk or a config file), and passphrase-protected keys cannot be
// decrypted by a non-interactive collector.
func DescribeKeyError(path string, err error) error {
	label := "ssh key"
	if path != "" {
		label = "ssh key " + path
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no key found"):
		return fmt.Errorf("%s: no PEM private key found — the file is not a usable private key (a *.pub public key, PuTTY .ppk or config file won't work; point the key path at the PRIVATE key)", label)
	case strings.Contains(msg, "passphrase"), strings.Contains(msg, "encrypted"):
		return fmt.Errorf("%s: passphrase-protected private keys are not supported — use a passphrase-less key or password auth", label)
	default:
		return fmt.Errorf("%s: %s", label, msg)
	}
}

// Run executes one command and returns stdout.
func (c *SSHClient) Run(ctx context.Context, host SSHHostConfig, cmd string) (string, error) {
	methods, err := c.authMethods()
	if err != nil {
		return "", err
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	port := host.Port
	if port <= 0 {
		port = 22
	}
	user := host.User
	if user == "" {
		user = c.User
	}
	if user == "" {
		user = "root"
	}
	var hkc ssh.HostKeyCallback
	if c.InsecureHostKey {
		hkc = ssh.InsecureIgnoreHostKey() //nolint:gosec // explicit config choice, documented
	} else if c.HostKeyPinned != "" {
		pinned, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.HostKeyPinned + "\n"))
		if err != nil {
			return "", fmt.Errorf("ssh pinned host key: %w", err)
		}
		expected := pinned.Marshal()
		hkc = func(hostname string, _ net.Addr, key ssh.PublicKey) error {
			if string(key.Marshal()) != string(expected) {
				return fmt.Errorf("ssh host key mismatch for %s", hostname)
			}
			return nil
		}
	} else {
		return "", fmt.Errorf("ssh host key verification refused: enable 'Accept any host key' for this scan (insecure - lab use only), pin the host key (per-host pinned_key or the scanner connection's ssh_pinned_key), or set AEGIS_SSH_SCAN_HOST_KEY_POLICY=insecure")
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            methods,
		HostKeyCallback: hkc,
		Timeout:         timeout,
	}
	dialer := &net.Dialer{Timeout: timeout}
	// net.JoinHostPort brackets IPv6 literals correctly; Sprintf produced
	// 2001:db8::1:22 and every IPv6 SSH target failed to parse.
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host.Host, strconv.Itoa(port)))
	if err != nil {
		return "", fmt.Errorf("ssh dial %s: %w", host.Host, err)
	}
	sconn, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(host.Host, strconv.Itoa(port)), cfg)
	if err != nil {
		_ = conn.Close()
		return "", fmt.Errorf("ssh handshake %s: %w", host.Host, err)
	}
	client := ssh.NewClient(sconn, chans, reqs)
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session %s: %w", host.Host, err)
	}
	defer sess.Close()
	done := make(chan struct{})
	var out []byte
	var execErr error
	go func() {
		out, execErr = sess.Output(cmd)
		close(done)
	}()
	select {
	case <-ctx.Done():
		_ = client.Close()
		return "", ctx.Err()
	case <-done:
	}
	if execErr != nil {
		return string(out), fmt.Errorf("ssh exec %s: %w", host.Host, execErr)
	}
	return string(out), nil
}

// pkgCollector pairs a presence probe with its collection command.
type pkgCollector struct {
	probe   string
	collect string
	parse   func(string) []SSHPackage
}

// --- collector ---

// SSHCollector collects OS + package inventory from one host.
type SSHCollector struct {
	Runner SSHRunner
	Log    *slog.Logger
	// Timeout bounds the whole per-host collection.
	Timeout time.Duration
}

// Collect runs the distro-appropriate collectors on one host. Package
// enumeration follows the detected distro (dpkg/rpm/apk); when the OS
// release cannot be parsed the collector probes dpkg then rpm then apk —
// mirroring vuls' dispatch fallback — and reports OSOK=false honestly.
func (c *SSHCollector) Collect(ctx context.Context, host SSHHostConfig) SSHHostResult {
	start := time.Now()
	res := SSHHostResult{Host: host}
	ptimeout := c.Timeout
	if ptimeout <= 0 {
		ptimeout = 60 * time.Second
	}
	pctx, cancel := context.WithTimeout(ctx, ptimeout)
	defer cancel()

	// run executes one collector command and records it in the per-host
	// command log (fixed string, outcome, output line count) before
	// returning - every probe and collect is auditable end to end.
	run := func(cmd string) (string, error) {
		out, err := c.Runner.Run(pctx, host, cmd)
		entry := domain.SSHCommandRun{Cmd: cmd, OK: err == nil}
		switch {
		case err != nil:
			entry.Err = err.Error()
		case strings.TrimSpace(out) == "":
			entry.Lines = 0
		default:
			entry.Lines = strings.Count(strings.TrimRight(out, "\n"), "\n") + 1
		}
		res.Commands = append(res.Commands, entry)
		return out, err
	}

	osOut, osErr := run(osReleaseCmd)
	if osErr == nil {
		family, name, ver, ok := ParseOSReleaseHost(osOut)
		if ok {
			res.OSFamily, res.OSName, res.OSVersion, res.OSOK = family, name, ver, true
		}
	} else {
		res.Err = osErr.Error()
	}
	pkgCmds := []pkgCollector{
		{probe: whichDpkgCmd, collect: dpkgQueryCmd, parse: ParseDpkgQuery},
		{probe: whichRpmCmd, collect: rpmQueryCmd, parse: ParseRpmQA},
		{probe: whichApkCmd, collect: apkListCmd, parse: ParseApkList},
	}
	// Distro-first ordering: the detected distro's package manager is
	// probed exclusively (containers may carry several managers; the OS
	// release is authoritative for which inventory is the OS inventory).
	if res.OSOK {
		switch res.OSFamily {
		case fingerprinting.DistroAlpine:
			pkgCmds = []pkgCollector{{probe: whichApkCmd, collect: apkListCmd, parse: ParseApkList}}
		case fingerprinting.DistroDebian, fingerprinting.DistroUbuntu:
			pkgCmds = []pkgCollector{{probe: whichDpkgCmd, collect: dpkgQueryCmd, parse: ParseDpkgQuery}}
		default:
			pkgCmds = []pkgCollector{{probe: whichRpmCmd, collect: rpmQueryCmd, parse: ParseRpmQA}}
		}
	}
	for _, pc := range pkgCmds {
		probeOut, err := run(pc.probe)
		if err != nil || strings.TrimSpace(probeOut) == "" {
			if err != nil && res.Err == "" {
				res.Err = err.Error() // transport failure, not just absence
			}
			continue // package manager not present / unreachable
		}
		out, err := run(pc.collect)
		if err != nil {
			if c.Log != nil {
				c.Log.Warn("ssh package collection failed", "host", host.Host, "err", err)
			}
			if res.Err == "" {
				res.Err = err.Error()
			}
			continue
		}
		res.Packages = pc.parse(out)
		if len(res.Packages) > 0 {
			break // distro's package manager yielded inventory
		}
	}
	res.DurationMS = time.Since(start).Milliseconds()
	return res
}
