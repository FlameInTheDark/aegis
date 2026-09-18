//go:build !linux

package endpoint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
	"os"
)

// Non-Linux fallbacks (spec §18): windows/macOS collectors are best-effort
// and rely on native APIs added incrementally; documented assumption §191.

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// newCSRKeyPair generates the local keypair + CSR.
func newCSRKeyPair() (csrPEM, keyPEM string, err error) {
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
// Non-Linux collector fallbacks (spec §18, documented assumption §191):
// windows uses registry/WMI APIs in a future revision; macOS uses
// system_profiler/pkgutil. The basics below keep the agent functional.

// SoftwarePackages returns a minimal native-software sample on
// windows/macOS. Windows: none collected at "basic" level (privacy).
func (c *Collector) SoftwarePackages() []agentv1.SoftwareReport_Package {
	return nil
}

// ListeningSockets falls back to empty on windows/macOS pending native
// socket API integration.
func (c *Collector) ListeningSockets() []agentv1.NetworkStateReport_Socket {
	return nil
}

// DefaultGateways is a non-Linux fallback.
func (c *Collector) DefaultGateways() []string { return nil }

// DNSServers is a non-Linux fallback.
func (c *Collector) DNSServers() []string { return nil }

// SecurityPosture is a non-Linux fallback (explicit unknowns, never guesses).
func (c *Collector) SecurityPosture() *agentv1.SecurityPostureReport {
	return &agentv1.SecurityPostureReport{
		AgentId: c.Cfg.AgentID, DiskEncryption: "unknown",
		AutoUpdates: "unknown", SecureBoot: "unknown",
	}
}
