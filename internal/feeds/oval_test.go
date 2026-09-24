package feeds

import (
	"strings"
	"testing"
	"time"
)

// ovalFixture covers the four shapes the major distro feeds emit: Debian
// dpkginfo (fixed), Ubuntu dpkginfo (fixed, severity in advisory), RHEL
// rpminfo (fixed with epoch), Alpine apkinfo (fixed + an unfixed variant).
// Namespaced exactly like the real feeds.
const ovalFixture = `<?xml version="1.0" encoding="utf-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
  xmlns:linux="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"
  xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent">
  <generator><oval:product_name xmlns:oval="x">debian oval-definitions</oval:product_name>
    <oval:timestamp xmlns:oval="x">2024-09-15T08:12:00</oval:timestamp></generator>
  <definitions>
    <definition class="vulnerability" id="oval:org.debian:def:1001" version="1">
      <metadata><title>DSA-5710-1 openssh-server -- security update</title>
        <affected family="unix"><linux:platform>Debian 12</linux:platform></affected>
        <reference source="CVE" ref_id="CVE-2024-9999" ref_url="https://security-tracker.debian.org/tracker/CVE-2024-9999"/>
        <reference source="DSA" ref_id="DSA-5710-1" ref_url="https://www.debian.org/security/2024/dsa-5710"/>
        <description>An attacker could cause OpenSSH to crash or possibly execute arbitrary code.</description>
        <advisory from="security@debian.org"><issued date="2024-06-12"/></advisory>
      </metadata>
      <criteria><criterion test_ref="oval:org.debian:tst:2001" comment="openssh-server is less than 1:9.2p1-2+deb12u4"/></criteria>
    </definition>
    <definition class="vulnerability" id="oval:com.ubuntu:def:2002" version="1">
      <metadata><title>USN-6800-1 openssl vulnerability</title>
        <affected family="unix"><linux:platform>Ubuntu 22.04 LTS</linux:platform></affected>
        <reference source="CVE" ref_id="CVE-2024-8888" ref_url="https://ubuntu.com/security/CVE-2024-8888"/>
        <reference source="USN" ref_id="USN-6800-1" ref_url="https://ubuntu.com/security/notices/USN-6800-1"/>
        <description>OpenSSL could be made to crash or run programs if it received specially crafted input.</description>
        <advisory from="security@ubuntu.com"><severity>medium</severity><issued date="2024-06-05"/></advisory>
      </metadata>
      <criteria><criterion test_ref="oval:com.ubuntu:tst:3001" comment="libssl3 was installed"/></criteria>
    </definition>
    <definition class="vulnerability" id="oval:com.red.rhssa:def:3003" version="1">
      <metadata><title>RHSA-2024:1234: Moderate: curl security update</title>
        <affected family="unix"><platform>Red Hat Enterprise Linux 9</platform></affected>
        <reference source="RHSA" ref_id="RHSA-2024:1234" ref_url="https://access.redhat.com/errata/RHSA-2024:1234"/>
        <reference source="CVE" ref_id="CVE-2024-7777" ref_url="https://access.redhat.com/security/cve/cve-2024-7777"/>
        <description>curl is affected by an information disclosure flaw.</description>
        <advisory from="secalert@redhat.com"><severity>moderate</severity><issued date="2024-04-01"/></advisory>
      </metadata>
      <criteria><criterion test_ref="oval:com.red.rhssa:tst:4001" comment="curl is earlier than 0:7.76.1-31.el9"/></criteria>
    </definition>
    <definition class="vulnerability" id="oval:org.alsec:def:4004" version="1">
      <metadata><title>CVE-2024-6666 vulnerability</title>
        <affected family="unix"><linux:platform>Alpine Linux v3.18</linux:platform></affected>
        <reference source="CVE" ref_id="CVE-2024-6666" ref_url="https://security.alpinelinux.org/vuln/CVE-2024-6666"/>
        <reference source="ALSA" ref_id="ALSA-2024-6666" ref_url="https://security.alpinelinux.org/vuln/CVE-2024-6666"/>
        <description>zlib has a flaw allowing a buffer overflow.</description>
        <advisory from="security@alpinelinux.org"><severity>high</severity><issued date="2024-03-03"/></advisory>
      </metadata>
      <criteria><criterion test_ref="oval:org.alsec:tst:5001" comment="zlib is affected"/></criteria>
    </definition>
    <definition class="vulnerability" id="oval:org.alsec:def:4005" version="1">
      <metadata><title>CVE-2024-5555 vulnerability</title>
        <affected family="unix"><linux:platform>Alpine Linux v3.18</linux:platform></affected>
        <reference source="CVE" ref_id="CVE-2024-5555" ref_url="https://security.alpinelinux.org/vuln/CVE-2024-5555"/>
        <reference source="ALSA" ref_id="ALSA-2024-5555" ref_url="https://security.alpinelinux.org/vuln/CVE-2024-7777"/>
        <description>curl vulnerable, no fix released yet.</description>
        <advisory from="security@alpinelinux.org"><severity>medium</severity><issued date="2024-05-05"/></advisory>
      </metadata>
      <criteria><criterion test_ref="oval:org.alsec:tst:5002" comment="curl is affected, unfixed"/></criteria>
    </definition>
  </definitions>
  <tests>
    <linux:dpkginfo_test id="oval:org.debian:tst:2001" check="all">
      <object object_ref="oval:org.debian:obj:2101"/>
      <state state_ref="oval:org.debian:ste:2201"/>
    </linux:dpkginfo_test>
    <linux:dpkginfo_test id="oval:com.ubuntu:tst:3001" check="all">
      <object object_ref="oval:com.ubuntu:obj:3101"/>
      <state state_ref="oval:com.ubuntu:ste:3201"/>
    </linux:dpkginfo_test>
    <linux:rpminfo_test id="oval:com.red.rhssa:tst:4001" check="all">
      <object object_ref="oval:com.red.rhssa:obj:4101"/>
      <state state_ref="oval:com.red.rhssa:ste:4201"/>
    </linux:rpminfo_test>
    <linux:apkinfo_test id="oval:org.alsec:tst:5001" check="all">
      <object object_ref="oval:org.alsec:obj:5101"/>
      <state state_ref="oval:org.alsec:ste:5201"/>
    </linux:apkinfo_test>
    <linux:apkinfo_test id="oval:org.alsec:tst:5002" check="all">
      <object object_ref="oval:org.alsec:obj:5301"/>
    </linux:apkinfo_test>
  </tests>
  <objects>
    <linux:dpkginfo_object id="oval:org.debian:obj:2101"><linux:name>openssh-server</linux:name></linux:dpkginfo_object>
    <linux:dpkginfo_object id="oval:com.ubuntu:obj:3101"><linux:name>libssl3</linux:name></linux:dpkginfo_object>
    <linux:rpminfo_object id="oval:com.red.rhssa:obj:4101"><linux:name>curl</linux:name></linux:rpminfo_object>
    <linux:apkinfo_object id="oval:org.alsec:obj:5101"><linux:name>zlib</linux:name></linux:apkinfo_object>
    <linux:apkinfo_object id="oval:org.alsec:obj:5301"><linux:name>curl</linux:name></linux:apkinfo_object>
  </objects>
  <states>
    <linux:dpkginfo_state id="oval:org.debian:ste:2201"><linux:evr datatype="evr_string" operation="less than">0:1:9.2p1-2+deb12u4</linux:evr></linux:dpkginfo_state>
    <linux:dpkginfo_state id="oval:com.ubuntu:ste:3201"><linux:evr datatype="evr_string" operation="less than">3.0.2-0ubuntu1.15</linux:evr></linux:dpkginfo_state>
    <linux:rpminfo_state id="oval:com.red.rhssa:ste:4201"><linux:evr datatype="evr_string" operation="less than">0:7.76.1-31.el9</linux:evr></linux:rpminfo_state>
    <linux:apkinfo_state id="oval:org.alsec:ste:5201"><linux:version datatype="version" operation="less than">1.2.13-r1</linux:version></linux:apkinfo_state>
  </states>
</oval_definitions>`

func TestParseOVALFixture(t *testing.T) {
	rows, err := ParseOVAL(strings.NewReader(ovalFixture), "ubuntu", "22.04", "oval", "")
	if err != nil {
		t.Fatalf("ParseOVAL: %v", err)
	}
	if len(rows) != 5 {
		t.Fatalf("got %d rows, want 5: %+v", len(rows), rows)
	}
	byCVE := map[string]advisoryRow{}
	for _, r := range rows {
		byCVE[r.CVEID] = r
	}

	// Debian: fixed version with 0: epoch stripped, non-zero epoch kept.
	d := byCVE["CVE-2024-9999"]
	if d.PackageName != "openssh-server" || d.FixedVersion != "1:9.2p1-2+deb12u4" {
		t.Errorf("debian row wrong: %+v", d)
	}
	if d.AdvisoryID != "DSA-5710-1" || d.Severity != "" {
		t.Errorf("debian metadata wrong: %+v", d)
	}
	if d.PublishedAt == nil || !d.PublishedAt.Equal(time.Date(2024, 6, 12, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("debian issued date wrong: %+v", d.PublishedAt)
	}

	// Ubuntu: advisory severity captured.
	u := byCVE["CVE-2024-8888"]
	if u.PackageName != "libssl3" || u.FixedVersion != "3.0.2-0ubuntu1.15" || u.Severity != "medium" {
		t.Errorf("ubuntu row wrong: %+v", u)
	}

	// RHEL: 0: epoch stripped.
	r := byCVE["CVE-2024-7777"]
	if r.PackageName != "curl" || r.FixedVersion != "7.76.1-31.el9" {
		t.Errorf("rhel row wrong: %+v", r)
	}

	// Alpine fixed + unfixed variants.
	a := byCVE["CVE-2024-6666"]
	if a.PackageName != "zlib" || a.FixedVersion != "1.2.13-r1" {
		t.Errorf("alpine fixed row wrong: %+v", a)
	}
	af := byCVE["CVE-2024-5555"]
	if !af.NotFixedYet || af.FixedVersion != "" || af.PackageName != "curl" {
		t.Errorf("alpine unfixed row wrong: %+v", af)
	}
}

func TestParseOVALGarbage(t *testing.T) {
	if rows, err := ParseOVAL(strings.NewReader("<html>not oval</html>"), "debian", "12", "oval", ""); err != nil || len(rows) != 0 {
		t.Fatalf("garbage must parse to zero rows without error, got %d, %v", len(rows), err)
	}
	if _, err := ParseOVAL(strings.NewReader("<broken>"), "debian", "12", "oval", ""); err == nil {
		t.Fatal("malformed XML must error")
	}
}

func TestParseOvalSources(t *testing.T) {
	srcs := ParseOvalSources("ubuntu:22.04:https://x/y.oval.xml.bz2, debian:12:https://x/y.xml:gz, badinput")
	if len(srcs) != 2 {
		t.Fatalf("got %d sources, want 2", len(srcs))
	}
	if srcs[0].Family != "ubuntu" || srcs[0].Release != "22.04" || srcs[0].Compress != "bz2" {
		t.Errorf("source 0 wrong: %+v", srcs[0])
	}
	if srcs[1].Family != "debian" || srcs[1].Compress != "gz" {
		t.Errorf("source 1 wrong: %+v", srcs[1])
	}
}

func TestStripZeroEpoch(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"0:1.2.3-4", "1.2.3-4"},
		{"1:9.2p1-2", "1:9.2p1-2"},
		{"1.2.3", "1.2.3"},
	} {
		if got := stripZeroEpoch(tc.in); got != tc.want {
			t.Errorf("stripZeroEpoch(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
