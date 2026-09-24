package pkgversion

import "testing"

// ubuntu2510Inventory is a real collected package inventory from an
// Ubuntu 25.10 (Questing) host — the exact shapes the SSH collector
// feeds into CVE matching: epochs (1:2.16.0-7, 2:2.8.0-1ubuntu2,
// 5:29.7.2-...), tilde pre-releases and backport suffixes
// (20260601~25.10.1, 2.3.3-1~ubuntu.25.10~questing), plus-signs
// (+ds, +0.0.0~ubuntu24), letter-era spellings (3.0pl1) and the
// upstream-format OpenSSH release (10.0p2). Every one of them must
// parse under the Debian grammar — a single parse failure would leave
// the package unjudgeable at match time (incomparable, never guessed).
var ubuntu2510Inventory = [][2]string{
	{"3cpio", "0.10.2-0ubuntu1"},
	{"OpenSSH", "10.0p2"},
	{"adduser", "3.152ubuntu1"},
	{"amd64-microcode", "3.20251202.1ubuntu0.25.10.1"},
	{"apparmor", "5.0.0~alpha1-0ubuntu8"},
	{"apport", "2.33.1-0ubuntu3"},
	{"apport-core-dump-handler", "2.33.1-0ubuntu3"},
	{"apport-symptoms", "0.25"},
	{"appstream", "1.0.6-2"},
	{"apt", "3.1.6ubuntu2"},
	{"base-files", "14ubuntu3"},
	{"base-passwd", "3.6.7"},
	{"bash", "5.2.37-2ubuntu5"},
	{"bash-completion", "1:2.16.0-7"},
	{"bc", "1.07.1-4"},
	{"bcache-tools", "1.0.8-5build1"},
	{"bind9-dnsutils", "1:9.20.11-1ubuntu2.4"},
	{"bind9-host", "1:9.20.11-1ubuntu2.4"},
	{"bind9-libs", "1:9.20.11-1ubuntu2.4"},
	{"binutils", "2.45-7ubuntu1.2"},
	{"binutils-common", "2.45-7ubuntu1.2"},
	{"binutils-x86-64-linux-gnu", "2.45-7ubuntu1.2"},
	{"bolt", "0.9.8-1"},
	{"bpfcc-tools", "0.31.0+ds-7ubuntu2"},
	{"bpftool", "7.7.0+6.17.0-41.41"},
	{"bpftrace", "0.23.5-1ubuntu1"},
	{"bsdextrautils", "2.41-4ubuntu4.2"},
	{"bsdutils", "1:2.41-4ubuntu4.2"},
	{"btop", "1.3.2-0.1"},
	{"btrfs-progs", "6.16-2"},
	{"busybox-initramfs", "1:1.37.0-4ubuntu1"},
	{"busybox-static", "1:1.37.0-4ubuntu1"},
	{"ca-certificates", "20260601~25.10.1"},
	{"chrony", "4.7-1ubuntu1"},
	{"cloud-guest-utils", "0.33-1"},
	{"cloud-init", "25.3~2g890873f5-0ubuntu2"},
	{"cloud-init-base", "25.3~2g890873f5-0ubuntu2"},
	{"cloud-initramfs-copymods", "0.49"},
	{"cloud-initramfs-dyn-netconf", "0.49"},
	{"command-not-found", "23.04.0"},
	{"console-setup", "1.237ubuntu1"},
	{"console-setup-linux", "1.237ubuntu1"},
	{"containerd.io", "2.3.3-1~ubuntu.25.10~questing"},
	{"coreutils", "9.5-1ubuntu2+0.0.0~ubuntu24"},
	{"coreutils-from-uutils", "0.0.0~ubuntu24"},
	{"cpio", "2.15+dfsg-2ubuntu1"},
	{"crash", "8.0.6-1ubuntu2"},
	{"cron", "3.0pl1-196ubuntu2"},
	{"cron-daemon-common", "3.0pl1-196ubuntu2"},
	{"cryptsetup", "2:2.8.0-1ubuntu2"},
	{"cryptsetup-bin", "2:2.8.0-1ubuntu2"},
	{"cryptsetup-initramfs", "2:2.8.0-1ubuntu2"},
	{"curl", "8.14.1-2ubuntu1.5"},
	{"dash", "0.5.12-12ubuntu2"},
	{"dbus", "1.16.2-2ubuntu2"},
	{"dbus-bin", "1.16.2-2ubuntu2"},
	{"dbus-daemon", "1.16.2-2ubuntu2"},
	{"dbus-session-bus-common", "1.16.2-2ubuntu2"},
	{"dbus-system-bus-common", "1.16.2-2ubuntu2"},
	{"dbus-user-session", "1.16.2-2ubuntu2"},
	{"debconf", "1.5.91"},
	{"debconf-i18n", "1.5.91"},
	{"debianutils", "5.23.2"},
	{"dhcpcd-base", "1:10.2.4-4"},
	{"diffutils", "1:3.10-4"},
	{"dirmngr", "2.4.8-2ubuntu2.1"},
	{"distro-info", "1.14"},
	{"distro-info-data", "0.66ubuntu0.2"},
	{"dmeventd", "2:1.02.205-2ubuntu2"},
	{"dmidecode", "3.6-2"},
	{"dmsetup", "2:1.02.205-2ubuntu2"},
	{"docker-buildx-plugin", "0.36.1-1~ubuntu.25.10~questing"},
	{"docker-ce", "5:29.7.2-1~ubuntu.25.10~questing"},
	{"docker-ce-cli", "5:29.7.2-1~ubuntu.25.10~questing"},
}

func TestUbuntu2510InventoryParses(t *testing.T) {
	for _, pkg := range ubuntu2510Inventory {
		pv, err := ParseDebVersion(pkg[1])
		if err != nil {
			t.Errorf("%s %q: ParseDebVersion failed: %v", pkg[0], pkg[1], err)
			continue
		}
		if pv.Raw != pkg[1] {
			t.Errorf("%s: raw not preserved verbatim: %q != %q", pkg[0], pv.Raw, pkg[1])
		}
		if pv.Upstream == "" {
			t.Errorf("%s %q: upstream component empty", pkg[0], pkg[1])
		}
	}
}

// TestUbuntu2510InventoryOrdering pins the ordering decisions the
// matcher makes on real inventory shapes: revision-only security
// bumps, tilde backports, epochs and the OpenSSH upstream release.
func TestUbuntu2510InventoryOrdering(t *testing.T) {
	// Revision-only Ubuntu security upload: the fix is one revision ahead.
	bind9, _ := ParseDebVersion("1:9.20.11-1ubuntu2.4")
	bind9fix, _ := ParseDebVersion("1:9.20.11-1ubuntu2.5")
	if CompareDebParsed(bind9, bind9fix) != -1 {
		t.Error("installed 1:9.20.11-1ubuntu2.4 must sort below fixed 1:9.20.11-1ubuntu2.5")
	}

	// Tilde backport (ca-certificates 20260601~25.10.1) sorts BELOW the
	// plain release it pre-releases.
	ca, _ := ParseDebVersion("20260601~25.10.1")
	caBase, _ := ParseDebVersion("20260601")
	if CompareDebParsed(ca, caBase) != -1 {
		t.Error("20260601~25.10.1 must sort below 20260601 (tilde rule)")
	}

	// Epoch 5 (docker-ce) dominates any epoch-less comparison.
	docker, _ := ParseDebVersion("5:29.7.2-1~ubuntu.25.10~questing")
	dockerNoEpoch, _ := ParseDebVersion("29.7.2-1~ubuntu.25.10~questing")
	if CompareDebParsed(docker, dockerNoEpoch) != 1 {
		t.Error("epoch 5 must dominate the epoch-less same-upstream version")
	}

	// cloud-init: the tilde git-snapshot upstream sorts below 25.3 proper,
	// but the distro revision still orders inside the same upstream.
	ci, _ := ParseDebVersion("25.3~2g890873f5-0ubuntu2")
	ciUp, _ := ParseDebVersion("25.3")
	if CompareDebParsed(ci, ciUp) != -1 {
		t.Error("25.3~2g890873f5-0ubuntu2 must sort below upstream 25.3")
	}

	// OpenSSH appears in UPSTREAM form (10.0p2) in this inventory: the
	// Debian projection keeps it as the upstream component with no
	// revision, and the structured OpenSSH view is the one CVE bounds
	// ("affected < 10.5") are judged against.
	ssh, err := ParseDebVersion("10.0p2")
	if err != nil {
		t.Fatal(err)
	}
	if ssh.Upstream != "10.0p2" || ssh.Revision != "" || ssh.Epoch != 0 {
		t.Errorf("Debian projection of 10.0p2 = %+v, want upstream 10.0p2 only", ssh)
	}
	ov, err := ParseOpenSSHVersion("10.0p2")
	if err != nil {
		t.Fatal(err)
	}
	if ov.Major != 10 || ov.Minor != 0 || !ov.HasUpdate || ov.Update != 2 {
		t.Errorf("structured OpenSSH view = %+v, want {10, 0, update 2}", ov)
	}
	bound, _ := ParseOpenSSHVersion("10.5")
	if CompareOpenSSH(ov, bound) != -1 {
		t.Error("10.0p2 must sort below the CVE boundary 10.5")
	}
}
