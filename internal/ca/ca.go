// Package ca implements the minimal agent device CA: it issues
// short-lived device certificates from CSRs. In development a CA is
// bootstrapped automatically; production mounts the CA key via secrets.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Authority signs agent certificates.
type Authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	mu   sync.Mutex
}

// Load loads a CA cert/key PEM pair. If files do not exist and devOK is
// true, a CA is generated and persisted (development convenience only).
func Load(certPath, keyPath string, devOK bool) (*Authority, error) {
	if certPath == "" || keyPath == "" {
		return nil, errors.New("agent CA not configured: set AEGIS_AGENT_CA_CERT and AEGIS_AGENT_CA_KEY")
	}
	certPEM, err1 := os.ReadFile(certPath)
	keyPEM, err2 := os.ReadFile(keyPath)
	if err1 != nil || err2 != nil {
		if !devOK {
			return nil, fmt.Errorf("agent CA not configured: provide %s and %s", certPath, keyPath)
		}
		if err := generateCA(certPath, keyPath); err != nil {
			return nil, err
		}
		certPEM, err1 = os.ReadFile(certPath)
		keyPEM, err2 = os.ReadFile(keyPath)
		if err1 != nil || err2 != nil {
			return nil, errors.New("CA bootstrap failed")
		}
	}
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, errors.New("invalid CA PEM material")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return &Authority{cert: cert, key: key}, nil
}

// Issue signs a device certificate for a CSR.
func (a *Authority) Issue(csrPEM, agentID string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", errors.New("invalid CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", err
	}
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("CSR signature invalid: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return "", err
	}
	notBefore := time.Now().UTC().Add(-time.Minute)
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	tpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "aegis-agent-" + agentID, Organization: []string{"Aegis Platform"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, a.cert, csr.PublicKey, a.key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// CertPEM returns the CA certificate for distribution to verifiers.
func (a *Authority) CertPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw}))
}

// generateCA creates a dev CA with restrictive file permissions.
func generateCA(certPath, keyPath string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Aegis Agent CA (dev)"},
		NotBefore:             time.Now().UTC().Add(-time.Minute),
		NotAfter:              time.Now().UTC().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
}
