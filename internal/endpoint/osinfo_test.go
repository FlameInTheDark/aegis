// OS identity and address normalization: the composition logic is pure and
// platform-neutral, so the tests run everywhere. The per-platform readers
// (registry, os-release) are exercised on their own platforms.

package endpoint

import (
	"testing"

	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
)

// composeWindowsOS turns the raw registry values into the displayed OS
// name and release. The known quirk it must survive: Windows 11 builds
// still report "Windows 10" in ProductName, so the build number decides.
func TestComposeWindowsOS(t *testing.T) {
	cases := []struct {
		name        string
		product     string
		display     string
		build       string
		ubr         uint64
		hasUBR      bool
		wantName    string
		wantVersion string
	}{
		{
			name:    "windows 11 24h2 with update revision",
			product: "Windows 11 Pro", display: "24H2", build: "26100", ubr: 2894, hasUBR: true,
			wantName: "Windows 11 Pro", wantVersion: "24H2 (build 26100.2894)",
		},
		{
			name:    "windows 11 product name quirk is corrected by build number",
			product: "Windows 10 Pro", display: "25H2", build: "26200", ubr: 0, hasUBR: false,
			wantName: "Windows 11 Pro", wantVersion: "25H2 (build 26200)",
		},
		{
			name:    "genuine windows 10 keeps its name",
			product: "Windows 10 Pro", display: "22H2", build: "19045", ubr: 3570, hasUBR: true,
			wantName: "Windows 10 Pro", wantVersion: "22H2 (build 19045.3570)",
		},
		{
			name:    "pre-20H2 build without DisplayVersion falls back to the build",
			product: "Windows 10 Pro", display: "", build: "19045", ubr: 0, hasUBR: false,
			wantName: "Windows 10 Pro", wantVersion: "19045",
		},
		{
			name:    "missing product falls back to the family",
			product: "", display: "", build: "26100", ubr: 0, hasUBR: false,
			wantName: "Windows", wantVersion: "26100",
		},
		{
			name:    "server editions pass through untouched",
			product: "Windows Server 2022 Standard", display: "", build: "20348", ubr: 100, hasUBR: true,
			wantName: "Windows Server 2022 Standard", wantVersion: "20348.100",
		},
		{
			name:    "no build data leaves the version empty",
			product: "Windows 11 Home", display: "", build: "", ubr: 0, hasUBR: false,
			wantName: "Windows 11 Home", wantVersion: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, version := composeWindowsOS(tc.product, tc.display, tc.build, tc.ubr, tc.hasUBR)
			if name != tc.wantName || version != tc.wantVersion {
				t.Fatalf("composeWindowsOS = (%q, %q), want (%q, %q)", name, version, tc.wantName, tc.wantVersion)
			}
		})
	}
}

// Interface addresses arrive with prefix lengths and IPv6 zone suffixes;
// every consumer (identifier persistence, matching, primary-address
// selection) needs the bare literal.
func TestNormalizeIfaceAddr(t *testing.T) {
	cases := []struct{ in, want string }{
		{"192.168.1.80/24", "192.168.1.80"},
		{"fe80::1234%12/64", "fe80::1234"},
		{"fe80::1%eth0", "fe80::1"},
		{"2001:db8::5/128", "2001:db8::5"},
		{"10.0.0.5", "10.0.0.5"},
		{" 192.168.1.80 ", "192.168.1.80"},
		{"garbage", ""},
		{"", ""},
		{"/24", ""},
	}
	for _, tc := range cases {
		if got := normalizeIfaceAddr(tc.in); got != tc.want {
			t.Errorf("normalizeIfaceAddr(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// gopsutil's CIDR-form addresses used to be rejected wholesale by the
// primary-address fallback — the raw system form must qualify.
func TestPickPrimaryIPHandlesCIDRFormAddresses(t *testing.T) {
	ifaces := []*agentv1.Iface{
		ifc("loopback", "", "up", "127.0.0.1/8", "::1/128"),
		ifc("Ethernet", "aa:bb:cc:dd:ee:ff", "up", "169.254.5.5/16", "192.168.1.80/24", "fe80::1%12/64"),
	}
	if got := PickPrimaryIP("", ifaces); got != "192.168.1.80" {
		t.Fatalf("PickPrimaryIP = %q, want the LAN address from the CIDR-form report", got)
	}
}

func TestPickPrimaryIPHandlesCIDRFormIPv6Only(t *testing.T) {
	ifaces := []*agentv1.Iface{
		ifc("loopback", "", "up", "127.0.0.1/8"),
		ifc("eth0", "aa:bb:cc:dd:ee:ff", "up", "fe80::1%eth0/64", "2001:db8::5/64"),
	}
	if got := PickPrimaryIP("", ifaces); got != "2001:db8::5" {
		t.Fatalf("PickPrimaryIP = %q, want the global IPv6 from the CIDR-form report", got)
	}
}
