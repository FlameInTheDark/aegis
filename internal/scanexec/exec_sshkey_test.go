package scanexec

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sshKeyTestExecutor(keyPath, password string) *Executor {
	return &Executor{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		SSH: SSHSettings{KeyPath: keyPath, Password: password},
	}
}

func writeKeyFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "id_test")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestResolveSSHKeyNoKeyConfigured(t *testing.T) {
	keyPEM, err := sshKeyTestExecutor("", "").resolveSSHKey()
	if err != nil || keyPEM != nil {
		t.Fatalf("no key configured must yield (nil, nil), got (%v, %v)", keyPEM, err)
	}
}

func TestResolveSSHKeyUnreadableWithPasswordFallsBack(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	keyPEM, err := sshKeyTestExecutor(missing, "pw").resolveSSHKey()
	if err != nil {
		t.Fatalf("unreadable key with password fallback must not fail, got: %v", err)
	}
	if keyPEM != nil {
		t.Fatalf("dropped key must be nil, got %d bytes", len(keyPEM))
	}
}

func TestResolveSSHKeyUnreadableWithoutPasswordFails(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	_, err := sshKeyTestExecutor(missing, "").resolveSSHKey()
	if err == nil || !strings.Contains(err.Error(), "ssh key") {
		t.Fatalf("unreadable key without fallback must fail clearly, got: %v", err)
	}
}

func TestResolveSSHKeyGarbageWithPasswordFallsBack(t *testing.T) {
	p := writeKeyFile(t, "not a private key\n")
	keyPEM, err := sshKeyTestExecutor(p, "pw").resolveSSHKey()
	if err != nil || keyPEM != nil {
		t.Fatalf("garbage key with password must fall back, got (%v, %v)", keyPEM, err)
	}
}

func TestResolveSSHKeyGarbageWithoutPasswordFailsActionably(t *testing.T) {
	// A public-key line is the field failure actually seen: "ssh: no key found".
	p := writeKeyFile(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI public-key-line user@host\n")
	_, err := sshKeyTestExecutor(p, "").resolveSSHKey()
	if err == nil {
		t.Fatal("public key file without password fallback must fail")
	}
	for _, want := range []string{p, "no PEM private key found"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q must contain %q", err, want)
		}
	}
}

func TestResolveSSHKeyValidKeyIsUsed(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	p := writeKeyFile(t, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	got, err := sshKeyTestExecutor(p, "pw").resolveSSHKey()
	if err != nil {
		t.Fatalf("valid key must load: %v", err)
	}
	if !strings.Contains(string(got), "PRIVATE KEY") {
		t.Fatalf("valid key content expected, got %q", got)
	}
}
