package ca

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Empty paths must fail with a clear message (not `open :`), regardless of
// dev mode — the previous behavior tried os.ReadFile("") / os.WriteFile("")
// which surfaces as "The system cannot find the file specified." on Windows.
func TestLoadEmptyPathsRejected(t *testing.T) {
	for _, devOK := range []bool{true, false} {
		_, err := Load("", "", devOK)
		if err == nil {
			t.Fatalf("devOK=%v: expected error for empty paths", devOK)
		}
		if !strings.Contains(err.Error(), "AEGIS_AGENT_CA_CERT") {
			t.Errorf("devOK=%v: error should name the env vars, got: %v", devOK, err)
		}
	}
}

func TestLoadDevGeneratesAndReloads(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "agent-ca.crt"), filepath.Join(dir, "agent-ca.key")

	a1, err := Load(cert, key, true)
	if err != nil {
		t.Fatalf("first load (should generate dev CA): %v", err)
	}
	if _, err := os.Stat(cert); err != nil {
		t.Errorf("CA cert not persisted: %v", err)
	}
	if _, err := os.Stat(key); err != nil {
		t.Errorf("CA key not persisted: %v", err)
	}

	a2, err := Load(cert, key, true)
	if err != nil {
		t.Fatalf("second load (should read persisted CA): %v", err)
	}
	if string(a1.CertPEM()) != string(a2.CertPEM()) {
		t.Error("reloaded CA must be the same certificate, not a new one")
	}

	// devOK=false with existing files still loads (production path).
	if _, err := Load(cert, key, false); err != nil {
		t.Errorf("production load with mounted CA files failed: %v", err)
	}
}

func TestLoadProductionFailsOnMissingFiles(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(filepath.Join(dir, "nope.crt"), filepath.Join(dir, "nope.key"), false)
	if err == nil {
		t.Fatal("expected error when CA files are missing and devOK=false")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Errorf("unexpected error: %v", err)
	}
}
