//go:build linux

package endpoint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
)

// jsonMarshal is shared by the runtime.
func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// newCSRKeyPair generates the local keypair + CSR (private key stays local).
func newCSRKeyPair() (csrPEM, keyPEM string, err error) {
	return generateCSR()
}

// generateCSR creates an EC P-256 keypair and CSR without shelling out.
func generateCSR() (csrPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	tpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "aegis-endpoint"}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	priv := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(csr), string(priv), nil
}

// readJSON loads a JSON file if present.
func readJSON(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// writeJSON persists a JSON file with tight permissions.
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// ---------------------------------------------------------------------------
// Linux collectors: /proc, os-release, package managers.

// platformOSInfo parses /etc/os-release without shelling out: the family is
// the distribution ID, the display name the human PRETTY_NAME and the
// version the numeric VERSION_ID ("ubuntu", "Ubuntu 24.04.1 LTS", "24.04").
func platformOSInfo() (family, name, version string) {
	family, name, version = "linux", "", ""
	values := map[string]string{}
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return family, name, version
	}
	for _, line := range strings.Split(string(data), "\n") {
		for _, key := range []string{"ID=", "PRETTY_NAME=", "VERSION_ID="} {
			if rest, ok := strings.CutPrefix(line, key); ok {
				values[key] = strings.Trim(rest, "\"")
			}
		}
	}
	family, name, version = values["ID="], values["PRETTY_NAME="], values["VERSION_ID="]
	if family == "" {
		family = "linux"
	}
	return family, name, version
}

// ListeningSockets parses /proc/net/tcp and tcp6 (IPv4/IPv6 listening).
func (c *Collector) ListeningSockets() []agentv1.NetworkStateReport_Socket {
	var out []agentv1.NetworkStateReport_Socket
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if i == 0 {
				continue // header
			}
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			// state 04 = TCP_LISTEN
			if fields[3] != "0A" {
				continue
			}
			ip, port := parseHexAddr(fields[1])
			// Process name from /proc/<inode> lookup is best-effort; PID is
			// omitted (would require scanning all fds — costly). Documented.
			out = append(out, agentv1.NetworkStateReport_Socket{
				Protocol: "tcp", LocalIp: ip, LocalPort: int32(port),
			})
			if len(out) >= 512 { // bounded output
				return out
			}
		}
	}
	return out
}

// parseHexAddr decodes /proc hex "AABBCCDD:1F90" (little-endian v4).
func parseHexAddr(s string) (string, int) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0
	}
	port, _ := strconv.ParseInt(parts[1], 16, 32)
	hex := parts[0]
	if len(hex) == 8 {
		b := make([]byte, 4)
		for i := 0; i < 4; i++ {
			v, _ := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
			b[3-i] = byte(v) // little-endian
		}
		return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]), int(port)
	}
	return hex, int(port)
}

// DefaultGateways reads /proc/net/route.
func (c *Collector) DefaultGateways() []string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		hex := fields[2]
		b := make([]byte, 4)
		for i := 0; i < 4; i++ {
			v, _ := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
			b[3-i] = byte(v)
		}
		out = append(out, fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]))
	}
	return out
}

// DNSServers reads /etc/resolv.conf.
func (c *Collector) DNSServers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver ") {
			out = append(out, strings.TrimSpace(strings.TrimPrefix(line, "nameserver ")))
		}
	}
	return out
}

// SoftwarePackages enumerates dpkg/rpm/apk packages via direct binary
// invocation (no shell, arg arrays ).
func (c *Collector) SoftwarePackages() []agentv1.SoftwareReport_Package {
	run := func(bin string, args ...string) []string {
		ctxDone := false
		_ = ctxDone
		out, err := exec.Command(bin, args...).Output() // #nosec G204 -- fixed args
		if err != nil {
			return nil
		}
		return strings.Split(strings.TrimSpace(string(out)), "\n")
	}
	var out []agentv1.SoftwareReport_Package
	add := func(name, ver, ecosystem, source string) {
		if name == "" {
			return
		}
		out = append(out, agentv1.SoftwareReport_Package{
			Name: name, Version: ver, Ecosystem: ecosystem, Source: source,
		})
	}
	// dpkg (Debian/Ubuntu)
	for _, line := range run("/usr/bin/dpkg-query", "-W", "-f=${Package}\t${Version}\n") {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) == 2 {
			add(parts[0], parts[1], "os_debian", "dpkg")
		}
	}
	// rpm (RHEL/Fedora)
	for _, line := range run("/usr/bin/rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n") {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) == 2 {
			add(parts[0], parts[1], "os_rpm", "rpm")
		}
	}
	// apk (Alpine)
	for _, line := range run("/sbin/apk", "list", "--installed") {
		if idx := strings.Index(line, " "); idx > 0 {
			nameVer := line[:idx]
			if dash := strings.LastIndex(nameVer, "-"); dash > 0 {
				add(nameVer[:dash], nameVer[dash+1:], "os_alpine", "apk")
			}
		}
	}
	if len(out) > 2000 {
		out = out[:2000]
	}
	return out
}

// SecurityPosture reads /proc for basic indicators (best-effort).
func (c *Collector) SecurityPosture() *agentv1.SecurityPostureReport {
	p := &agentv1.SecurityPostureReport{
		AgentId:         c.Cfg.AgentID,
		DiskEncryption:  "unknown",
		AutoUpdates:     "unknown",
		SecureBoot:      "unknown",
		FirewallProduct: "unknown",
	}
	// Secure boot via efivars (best-effort).
	if data, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"); err == nil && len(data) > 4 {
		if data[4] == 1 {
			p.SecureBoot = "enabled"
		} else {
			p.SecureBoot = "disabled"
		}
	}
	// nftables presence heuristic (documented assumption: no netlink in v1).
	if _, err := os.Stat("/proc/net/nf_conntrack"); err == nil {
		p.FirewallEnabled = true
		p.FirewallProduct = "nftables"
	}
	return p
}
