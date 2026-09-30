package endpoint

import (
	"strings"
	"testing"
)

func TestParseWindowsDefaultGateways(t *testing.T) {
	sample := `
===========================================================================
Interface List
 1...........................Loopback
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.10     25
          0.0.0.0          0.0.0.0        On-link     192.168.1.10    281
     192.168.1.0  255.255.255.0        On-link     192.168.1.10    281
===========================================================================
`
	gw := parseWindowsDefaultGateways(sample)
	if len(gw) != 1 || gw[0] != "192.168.1.1" {
		t.Fatalf("got %v, want [192.168.1.1] (On-link skipped)", gw)
	}
}

func TestParseDarwinDefaultGateways(t *testing.T) {
	sample := `Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            10.0.0.1           UGScg          en0
default            10.0.0.1           UGScg          en0
0/1                10.0.0.1           UGScg          en0
10.0.0/24          link#4             UCS            en0
`
	gw := parseDarwinDefaultGateways(sample)
	if len(gw) != 1 || gw[0] != "10.0.0.1" {
		t.Fatalf("got %v, want unique [10.0.0.1]", gw)
	}
}

func TestParseResolvConf(t *testing.T) {
	sample := "# comment\nnameserver 10.0.0.53\nnameserver 10.0.0.53\nnameserver fd00::1\nsearch corp.example\n"
	ns := parseResolvConf(sample)
	if len(ns) != 2 {
		t.Fatalf("got %v, want 2 unique nameservers", ns)
	}
	if ns[0] != "10.0.0.53" || !strings.HasPrefix(ns[1], "fd00") {
		t.Fatalf("nameservers: %v", ns)
	}
}

func TestDockerSocketPathFor(t *testing.T) {
	if got := dockerSocketPathFor(""); got != "/var/run/docker.sock" {
		t.Fatalf("default: %s", got)
	}
	if got := dockerSocketPathFor("unix:///var/run/docker-test.sock"); got != "/var/run/docker-test.sock" {
		t.Fatalf("unix://: %s", got)
	}
	if got := dockerSocketPathFor("tcp://127.0.0.1:2375"); got != "/var/run/docker.sock" {
		t.Fatalf("tcp hosts are not honored from the agent: %s", got)
	}
}

func TestParseDockerContainers(t *testing.T) {
	sample := []byte(`[
          {"Id":"abc123","Names":["/web-1"],"Image":"nginx:1.25","ImageID":"sha256:deadbeef","State":"running"},
          {"Id":"def456","Names":[],"Image":"redis:7","ImageID":"sha256:cafe","State":"running"},
          {"Id":"ghi789","Names":["/worker"],"Image":"","ImageID":"sha256:f00d","State":"paused"}
        ]`)
	pkgs := parseDockerContainers(sample)
	if len(pkgs) != 3 {
		t.Fatalf("got %d packages, want 3", len(pkgs))
	}
	if pkgs[0].Name != "docker/web-1" || pkgs[0].Version != "sha256:deadbeef" || pkgs[0].Vendor != "docker" || pkgs[0].Source != "container" {
		t.Fatalf("pkg0: name=%q version=%q vendor=%q source=%q", pkgs[0].Name, pkgs[0].Version, pkgs[0].Vendor, pkgs[0].Source)
	}
	if pkgs[1].Name != "docker/redis:7" {
		t.Fatalf("unnamed container falls back to image: name=%q", pkgs[1].Name)
	}
	if bad := parseDockerContainers([]byte("not json")); bad != nil {
		t.Fatalf("garbage should parse to nil, got %d", len(bad))
	}
}
