package scanning

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

// validPrivateKeyPEM mints a throwaway ed25519 key as PKCS#8 PEM —
// ssh.ParsePrivateKey accepts it, so tests exercise the success path.
func validPrivateKeyPEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// Regression: a configured-but-unusable key used to hard-fail authMethods
// before the password method was ever tried — scanning with login+password
// failed with "ssh key: ssh: no key found" whenever a stale key path (often
// pointing at a *.pub public key) was present in the configuration.
func TestAuthMethodsPasswordSurvivesBrokenKey(t *testing.T) {
	c := &SSHClient{Password: "secret", KeyPEM: []byte("this is not a key")}
	methods, err := c.authMethods()
	if err != nil {
		t.Fatalf("password auth must survive an unusable key, got: %v", err)
	}
	if len(methods) != 2 { // ssh.Password + keyboard-interactive
		t.Fatalf("want password + keyboard-interactive, got %d methods", len(methods))
	}
}

func TestAuthMethodsBrokenKeyOnlyFailsActionably(t *testing.T) {
	c := &SSHClient{KeyPEM: []byte("garbage"), KeyPath: "/keys/id_rsa"}
	_, err := c.authMethods()
	if err == nil {
		t.Fatal("a broken key with no password fallback must fail")
	}
	for _, want := range []string{"/keys/id_rsa", "private key"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q must mention %q", err, want)
		}
	}
}

func TestAuthMethodsValidKey(t *testing.T) {
	c := &SSHClient{KeyPEM: validPrivateKeyPEM(t)}
	methods, err := c.authMethods()
	if err != nil {
		t.Fatalf("valid key must parse, got: %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("want 1 method, got %d", len(methods))
	}
}

func TestAuthMethodsValidKeyWithPassword(t *testing.T) {
	c := &SSHClient{KeyPEM: validPrivateKeyPEM(t), Password: "pw"}
	methods, err := c.authMethods()
	if err != nil {
		t.Fatalf("valid key + password must parse, got: %v", err)
	}
	if len(methods) != 3 { // key + password + keyboard-interactive
		t.Fatalf("want 3 methods, got %d", len(methods))
	}
}

func TestDescribeKeyErrorHints(t *testing.T) {
	cases := []struct {
		name string
		err  error
		path string
		want []string
	}{
		{"public key file", errors.New("ssh: no key found"), "/keys/id_rsa.pub",
			[]string{"/keys/id_rsa.pub", "no PEM private key found", "*.pub"}},
		{"no path label", errors.New("ssh: no key found"), "",
			[]string{"ssh key:", "no PEM private key found"}},
		{"encrypted key", errors.New("ssh: cannot decode encrypted private keys"), "/keys/id_rsa",
			[]string{"/keys/id_rsa", "passphrase-protected"}},
		{"passphrase protected", errors.New("ssh: this private key is passphrase protected"), "",
			[]string{"passphrase-protected"}},
		{"passthrough", errors.New("asn1: syntax error"), "/keys/odd",
			[]string{"/keys/odd", "asn1: syntax error"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DescribeKeyError(tc.path, tc.err).Error()
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Fatalf("message %q must contain %q", got, w)
				}
			}
		})
	}
}
