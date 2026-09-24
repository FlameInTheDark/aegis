package fingerprinting

import "testing"

func TestDistroOf(t *testing.T) {
	tests := []struct {
		name        string
		osFamily    string
		osName      string
		osVersion   string
		wantFamily  string
		wantRelease string
		wantPkgEco  string
		wantOk      bool
	}{
		{name: "canonical family field wins", osFamily: "ubuntu", osVersion: "22.04",
			wantFamily: "ubuntu", wantRelease: "22.04", wantPkgEco: "os_debian", wantOk: true},
		{name: "display-name family field", osFamily: "Ubuntu Linux", osVersion: "24.04",
			wantFamily: "ubuntu", wantRelease: "24.04", wantPkgEco: "os_debian", wantOk: true},
		{name: "rhel alias", osFamily: "rhel", osVersion: "9.3",
			wantFamily: "rhel", wantRelease: "9", wantPkgEco: "os_rpm", wantOk: true},
		{name: "alpine family field truncates micro", osFamily: "alpine", osVersion: "3.18.0",
			wantFamily: "alpine", wantRelease: "3.18", wantPkgEco: "os_alpine", wantOk: true},
		{name: "rhel release keys major only", osFamily: "Red Hat Enterprise Linux", osVersion: "9.3",
			wantFamily: "rhel", wantRelease: "9", wantPkgEco: "os_rpm", wantOk: true},
		{name: "family without release is not enough", osFamily: "ubuntu",
			wantOk: false},
		{name: "unknown family field ignored, name mined", osFamily: "linux",
			osName: "Ubuntu 22.04.3 LTS", wantFamily: "ubuntu", wantRelease: "22.04",
			wantPkgEco: "os_debian", wantOk: true},
		{name: "scanner string ubuntu", osName: "Ubuntu 22.04",
			wantFamily: "ubuntu", wantRelease: "22.04", wantPkgEco: "os_debian", wantOk: true},
		{name: "scanner string debian pretty", osName: "Debian GNU/Linux 12 (bookworm)",
			wantFamily: "debian", wantRelease: "12", wantPkgEco: "os_debian", wantOk: true},
		{name: "scanner string debian codename only rejected", osName: "Debian GNU/Linux bookworm",
			wantOk: false},
		{name: "scanner string alpine", osName: "Alpine Linux 3.18",
			wantFamily: "alpine", wantRelease: "3.18", wantPkgEco: "os_alpine", wantOk: true},
		{name: "scanner string alpine v-prefix", osName: "Alpine Linux v3.18",
			wantFamily: "alpine", wantRelease: "3.18", wantPkgEco: "os_alpine", wantOk: true},
		{name: "scanner string rhel long form", osName: "Red Hat Enterprise Linux 9.3",
			wantFamily: "rhel", wantRelease: "9", wantPkgEco: "os_rpm", wantOk: true},
		{name: "scanner string rocky", osName: "Rocky Linux 8.9", osVersion: "",
			wantFamily: "rocky", wantRelease: "8", wantPkgEco: "os_rpm", wantOk: true},
		{name: "osVersion used when name has none", osName: "Debian GNU/Linux",
			osVersion: "12.5", wantFamily: "debian", wantRelease: "12",
			wantPkgEco: "os_debian", wantOk: true},
		{name: "windows never resolves", osName: "Microsoft Windows Server 2022",
			wantOk: false},
		{name: "empty everything", wantOk: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := DistroOf(tc.osFamily, tc.osName, tc.osVersion)
			if ok != tc.wantOk {
				t.Fatalf("ok = %v, want %v (got %+v)", ok, tc.wantOk, got)
			}
			if !tc.wantOk {
				return
			}
			if got.Family != tc.wantFamily || got.Release != tc.wantRelease || got.PkgEcosystem != tc.wantPkgEco {
				t.Fatalf("got %+v, want family=%s release=%s pkgEco=%s",
					got, tc.wantFamily, tc.wantRelease, tc.wantPkgEco)
			}
		})
	}
}

func TestParseOSRelease(t *testing.T) {
	// Canonical /etc/os-release shapes (vuls dispatch fixtures).
	tests := []struct {
		name        string
		stdout      string
		wantFamily  string
		wantRelease string
		wantOK      bool
	}{
		{
			name:       "ubuntu",
			stdout:     "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"22.04\"\nPRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\n",
			wantFamily: "ubuntu", wantRelease: "22.04", wantOK: true,
		},
		{
			name:   "debian with sid fallback",
			stdout: "PRETTY_NAME=\"Debian GNU/Linux trixie/sid\"\nID=debian\n",
			wantOK: false, // no VERSION_ID — release unknown, never guess
		},
		{
			name:       "debian versioned",
			stdout:     "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n",
			wantFamily: "debian", wantRelease: "12", wantOK: true,
		},
		{
			name:       "alpine",
			stdout:     "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.18.0\n",
			wantFamily: "alpine", wantRelease: "3.18", wantOK: true,
		},
		{
			name:       "rhel",
			stdout:     "NAME=\"Red Hat Enterprise Linux\"\nID=rhel\nVERSION_ID=\"9.3\"\n",
			wantFamily: "rhel", wantRelease: "9", wantOK: true,
		},
		{
			name:       "amazon linux",
			stdout:     "NAME=\"Amazon Linux\"\nID=amzn\nVERSION_ID=\"2023\"\n",
			wantFamily: "amazon", wantRelease: "2023", wantOK: true,
		},
		{
			name:   "unknown distro",
			stdout: "NAME=\"Widget OS\"\nID=widgetos\nVERSION_ID=\"1.0\"\n",
			wantOK: false,
		},
		{name: "garbage", stdout: "not an os-release file", wantOK: false},
		{name: "empty", stdout: "", wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseOSRelease(tc.stdout)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (got %+v)", ok, tc.wantOK, got)
			}
			if !tc.wantOK {
				return
			}
			if got.Family != tc.wantFamily || got.Release != tc.wantRelease {
				t.Fatalf("got %+v, want family=%s release=%s", got, tc.wantFamily, tc.wantRelease)
			}
		})
	}
}

func TestNormalizeRelease(t *testing.T) {
	tests := []struct{ in, want string }{
		{"22.04 LTS", "22.04"},
		{"v3.18", "3.18"},
		{"12 (bookworm)", "12"},
		{"9.3", "9.3"},
		{"2023", "2023"},
		{"", ""},
		{"bookworm", ""},
		{"..", ""},
	}
	for _, tc := range tests {
		if got := normalizeRelease(tc.in); got != tc.want {
			t.Errorf("normalizeRelease(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDistroOfNoPanic covers the free-form OS strings the demo seed and
// real fingerprints produce (a padded-index slicing bug crashed the server on
// "pfSense" — these inputs are the regression guard).
func TestDistroOfNoPanic(t *testing.T) {
	inputs := []string{
		"pfSense", "MikroTik RouterOS", "Cisco IOS", "VMware ESXi",
		"Dahua firmware", "Synology DSM", "HP LaserJet", "Windows 11 Pro",
		"Windows 10 Pro", "macOS Sonoma", "Ubuntu Server", "Debian",
		"Ubuntu 22.04", "Debian GNU/Linux 12 (bookworm)", "Alpine Linux v3.18",
		"Red Hat Enterprise Linux 9.3", "openSUSE Leap 15.5", "SUSE Linux Enterprise Server 15",
		"Amazon Linux 2023", "Rocky Linux 8.9", "CentOS Stream", "Fedora Linux 40",
		"", "x", "os", "a b c", "!!!", "s u s e", "opensuseleap",
	}
	for _, name := range inputs {
		for _, fam := range []string{"", "linux", "other", "ubuntu", "windows", "darwin"} {
			for _, ver := range []string{"", "1", "22.04", "2.7"} {
				seg, ok := DistroOf(fam, name, ver)
				if ok {
					if seg.Family == "" || seg.Release == "" || seg.PkgEcosystem == "" {
						t.Fatalf("incomplete segment for %q/%q/%q: %+v", fam, name, ver, seg)
					}
				}
			}
		}
	}
	// Specific known outcomes for the demo fleet.
	if seg, ok := DistroOf("linux", "pfSense", "2.7"); ok {
		t.Errorf("pfSense resolved to %+v, want no resolution", seg)
	}
	if seg, ok := DistroOf("linux", "Ubuntu Server", "24.04"); !ok || seg.Family != "ubuntu" || seg.Release != "24.04" {
		t.Errorf("Ubuntu Server 24.04 got %+v ok=%v", seg, ok)
	}
	if seg, ok := DistroOf("linux", "Debian", "12"); !ok || seg.Family != "debian" || seg.Release != "12" {
		t.Errorf("Debian 12 got %+v ok=%v", seg, ok)
	}
	// "openSUSE" must resolve via its own alias, not bare "suse".
	if seg, ok := DistroOf("", "openSUSE Leap 15.5", ""); !ok || seg.Family != fingerprintOpenSUSE() {
		t.Errorf("openSUSE got %+v ok=%v", seg, ok)
	}
}

func fingerprintOpenSUSE() string { return DistroOpenSUSE }
