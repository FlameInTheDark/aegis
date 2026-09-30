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
	"os"

	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
	gnet "github.com/shirou/gopsutil/v4/net"
)

// Cross-platform helpers shared by the non-Linux collectors.

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

// securityPostureUnknown is the explicit-unknown posture report: posture
// values are never inferred to fill a card (improvement plan 4.12).
func securityPostureUnknown(agentID string) *agentv1.SecurityPostureReport {
	return &agentv1.SecurityPostureReport{
		AgentId: agentID, DiskEncryption: "unknown",
		AutoUpdates: "unknown", SecureBoot: "unknown",
	}
}

// listeningSocketsViaGopsutil enumerates listening TCP endpoints through
// gopsutil, which maps to the IP helper APIs on Windows and sysctl on
// macOS. PID/process-name are deliberately omitted: the platform does not
// trust agent-side process attribution beyond the endpoint itself.
func listeningSocketsViaGopsutil() []agentv1.NetworkStateReport_Socket {
	conns, err := gnet.Connections("tcp")
	if err != nil {
		return nil
	}
	out := make([]agentv1.NetworkStateReport_Socket, 0, 64)
	for _, n := range conns {
		if n.Status != "LISTEN" {
			continue
		}
		out = append(out, agentv1.NetworkStateReport_Socket{
			Protocol:  "tcp",
			LocalIp:   n.Laddr.IP,
			LocalPort: int32(n.Laddr.Port),
		})
		if len(out) >= 512 {
			break
		}
	}
	return out
}

// Containers is a no-op off Linux: the Docker-compatible socket walk is a
// Linux collector capability (F9).
func (c *Collector) Containers() []agentv1.SoftwareReport_Package { return nil }
