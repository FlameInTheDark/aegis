package scanning

import (
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// The user-visible symptom was "no OS data in the app" on hosts where nmap
// prints "Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel" — the OS
// CPE attached to service fingerprints is the only OS signal when raw -O
// probes are filtered (typical for container-born scans).
func TestOSFamilyFromCPE(t *testing.T) {
	cases := []struct {
		cpe        string
		family     string
		name       string
		consistent bool
	}{
		{cpe: "cpe:/o:linux:linux_kernel", family: "linux", name: "Linux", consistent: true},
		{cpe: "cpe:/o:linux:linux_kernel:5.4", family: "linux", name: "Linux", consistent: true},
		{cpe: "cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*", family: "linux", name: "Linux", consistent: true},
		{cpe: "cpe:/o:microsoft:windows_10:1909", family: "windows", name: "Windows", consistent: true},
		{cpe: "cpe:/o:apple:macos:14", family: "macos", name: "macOS", consistent: true},
		{cpe: "cpe:/o:freebsd:freebsd:14.0", family: "bsd", name: "FreeBSD", consistent: true},
		{cpe: "cpe:/o:cisco:ios:15.2", family: "cisco-ios", name: "Cisco IOS", consistent: true},
		// Application and hardware CPEs must never claim an OS family.
		{cpe: "cpe:/a:openbsd:openssh:10.0p2", consistent: false},
		{cpe: "cpe:/h:dell:poweredge", consistent: false},
		{cpe: "", consistent: false},
		{cpe: "garbage", consistent: false},
	}
	for _, tc := range cases {
		family, name, ok := osFamilyFromCPE(tc.cpe)
		if tc.consistent {
			if !ok {
				t.Errorf("osFamilyFromCPE(%q) = not ok, want ok", tc.cpe)
				continue
			}
			if family != tc.family || name != tc.name {
				t.Errorf("osFamilyFromCPE(%q) = (%q, %q), want (%q, %q)", tc.cpe, family, name, tc.family, tc.name)
			}
		} else if ok {
			t.Errorf("osFamilyFromCPE(%q) = ok, want not ok", tc.cpe)
		}
	}
}

// The software bridge converts -sV fingerprints into software rows; bare
// service names without any version/product/CPE carry no software
// information and must not pollute the inventory.
func TestSoftwareFromService(t *testing.T) {
	// OpenSSH on Linux: application CPE + OS CPE (OS CPE excluded).
	svc := &domain.Service{
		ServiceName:     "ssh",
		Product:         "OpenSSH",
		Vendor:          "OpenBSD",
		DetectedVersion: "10.0p2",
		CPEs:            []string{"cpe:/a:openbsd:openssh:10.0p2", "cpe:/o:linux:linux_kernel"},
	}
	sw := softwareFromService(svc)
	if sw == nil {
		t.Fatal("softwareFromService(OpenSSH) = nil, want software row")
	}
	if sw.Name != "OpenSSH" || sw.Version != "10.0p2" || sw.Vendor != "OpenBSD" {
		t.Errorf("unexpected software row: %+v", sw)
	}
	if sw.Ecosystem != "cpe" || sw.Source != "nmap" {
		t.Errorf("unexpected provenance: %+v", sw)
	}
	if len(sw.CPEs) != 1 || sw.CPEs[0] != "cpe:/a:openbsd:openssh:10.0p2" {
		t.Errorf("OS CPE must be excluded from software: %v", sw.CPEs)
	}

	// rpcbind without product but with a version is still meaningful.
	sw = softwareFromService(&domain.Service{ServiceName: "rpcbind", DetectedVersion: "2-4"})
	if sw == nil {
		t.Fatal("softwareFromService(rpcbind 2-4) = nil, want software row")
	}
	if sw.Name != "rpcbind" || sw.Version != "2-4" {
		t.Errorf("unexpected software row: %+v", sw)
	}

	// A bare "http" with no product/version/CPE is noise.
	if sw := softwareFromService(&domain.Service{ServiceName: "http"}); sw != nil {
		t.Errorf("softwareFromService(bare http) = %+v, want nil", sw)
	}
	if sw := softwareFromService(nil); sw != nil {
		t.Errorf("softwareFromService(nil) = %+v, want nil", sw)
	}
}

// The "cpes" payload key arrives as []string from in-memory observations and
// as []any after a JSON round-trip; both shapes must resolve.
func TestCPEList(t *testing.T) {
	if got := cpeList([]string{"cpe:/o:linux:linux_kernel"}); len(got) != 1 {
		t.Errorf("cpeList([]string) = %v", got)
	}
	got := cpeList([]any{"cpe:/o:linux:linux_kernel", 42, "cpe:/a:openbsd:openssh"})
	if len(got) != 2 {
		t.Errorf("cpeList([]any) = %v, want 2 entries", got)
	}
	if got := cpeList("not-a-list"); got != nil {
		t.Errorf("cpeList(string) = %v, want nil", got)
	}
	if got := cpeList(nil); got != nil {
		t.Errorf("cpeList(nil) = %v, want nil", got)
	}
}
