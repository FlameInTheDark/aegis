package scanning

import (
	"strings"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

func TestValidateSSHHostsEmptyListFallsBack(t *testing.T) {
	out, err := ValidateSSHHosts(nil, 256)
	if err != nil {
		t.Fatalf("empty list must be valid (scanner-config fallback): %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected no targets, got %d", len(out))
	}
}

func TestValidateSSHHostsNormalizesAndDefaultsAuth(t *testing.T) {
	out, err := ValidateSSHHosts([]domain.SSHScanHost{
		{Host: " 10.0.0.5 ", Port: 2222, Username: " scan ", Password: "s3cret"},
		{Host: "web.local", Username: "deploy", KeyPEM: "-----BEGIN OPENSSH PRIVATE KEY-----"},
	}, 256)
	if err != nil {
		t.Fatalf("valid mixed-auth list rejected: %v", err)
	}
	if out[0].Host != "10.0.0.5" || out[0].Username != "scan" || out[0].Auth != domain.SSHAuthPassword {
		t.Fatalf("password host not normalized: %+v", out[0])
	}
	if out[1].Auth != domain.SSHAuthKey {
		t.Fatalf("key auth not derived from key material: %+v", out[1])
	}
}

func TestValidateSSHHostsRejects(t *testing.T) {
	cases := []struct {
		name string
		host domain.SSHScanHost
		want string
	}{
		{"missing host", domain.SSHScanHost{Username: "u", Password: "p"}, "host is required"},
		{"missing user", domain.SSHScanHost{Host: "h", Password: "p"}, "username is required"},
		{"password auth without password", domain.SSHScanHost{Host: "h", Username: "u", Auth: domain.SSHAuthPassword}, "password is required"},
		{"key auth without key", domain.SSHScanHost{Host: "h", Username: "u", Auth: domain.SSHAuthKey}, "private key is required"},
		{"both secrets", domain.SSHScanHost{Host: "h", Username: "u", Password: "p", KeyPEM: "k"}, "either password or key"},
		{"bad auth", domain.SSHScanHost{Host: "h", Username: "u", Auth: "agent", Password: "p"}, `auth must be "password" or "key"`},
		{"port range", domain.SSHScanHost{Host: "h", Port: 70000, Username: "u", Password: "p"}, "port must be between"},
		{"host whitespace", domain.SSHScanHost{Host: "a b", Username: "u", Password: "p"}, "whitespace"},
		{"dup", domain.SSHScanHost{Host: "h", Username: "u", Password: "p"}, "duplicate target"},
	}
	// The dup case needs a pre-existing identical target.
	dupBase := domain.SSHScanHost{Host: "h", Username: "u", Password: "p"}
	for _, tc := range cases {
		hosts := []domain.SSHScanHost{tc.host}
		if tc.name == "dup" {
			hosts = []domain.SSHScanHost{dupBase, tc.host}
		}
		_, err := ValidateSSHHosts(hosts, 256)
		if err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: error %q does not mention %q", tc.name, err.Error(), tc.want)
		}
	}
}

func TestValidateSSHHostsMaxEntries(t *testing.T) {
	hosts := make([]domain.SSHScanHost, 257)
	for i := range hosts {
		hosts[i] = domain.SSHScanHost{Host: "10.0.0.1", Username: "u", Password: "p"}
	}
	if _, err := ValidateSSHHosts(hosts, 256); err == nil {
		t.Fatal("expected max-entries error")
	}
}

func TestValidateSSHHostsPinnedKey(t *testing.T) {
	pinned := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExampleExampleExampl"
	hosts := []domain.SSHScanHost{{Host: "10.0.0.5", Username: "root", Password: "p", PinnedKey: pinned}}
	out, err := ValidateSSHHosts(hosts, 256)
	if err != nil {
		t.Fatalf("pinned key must be accepted: %v", err)
	}
	if out[0].PinnedKey != pinned {
		t.Fatalf("pinned key must round-trip, got %q", out[0].PinnedKey)
	}
	big := make([]byte, 8<<10+1)
	for i := range big {
		big[i] = 'A'
	}
	_, err = ValidateSSHHosts([]domain.SSHScanHost{{Host: "10.0.0.5", Username: "root", Password: "p", PinnedKey: string(big)}}, 256)
	if err == nil {
		t.Fatal("oversized pinned key must be rejected")
	}
	if !strings.Contains(err.Error(), "pinned_key") {
		t.Fatalf("error must mention pinned_key: %v", err)
	}
}
