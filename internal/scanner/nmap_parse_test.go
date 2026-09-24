package scanner

import (
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

func TestParseNmapTraceroute(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host starttime="1">
 <status state="up" reason="reset"/>
 <address addr="192.168.1.55" addrtype="ipv4"/>
 <trace proto="icmp">
  <hop ttl="1" ipaddr="192.168.1.1" rtt="1.23"/>
  <hop ttl="2" ipaddr="10.0.0.1" host="rtr-core" rtt="4.56"/>
  <hop ttl="3" ipaddr="192.168.1.55" rtt="5.0"/>
 </trace>
</host>
</nmaprun>`
	hops, err := parseNmapTraceroute([]byte(xml), "192.168.1.55")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(hops) != 3 {
		t.Fatalf("want 3 hops, got %d: %+v", len(hops), hops)
	}
	if hops[0].IP != "192.168.1.1" || hops[0].TTL != 1 {
		t.Errorf("hop0 = %+v", hops[0])
	}
	if hops[1].Hostname != "rtr-core" {
		t.Errorf("hop1 hostname = %q", hops[1].Hostname)
	}
	if hops[2].IP != "192.168.1.55" {
		t.Errorf("last hop must be target, got %+v", hops[2])
	}
}

func TestParseNmapTracerouteAppendsTarget(t *testing.T) {
	// When nmap cannot see the final hop it omits it; the parser must append
	// the target so the graph always reaches the host.
	xml := `<nmaprun><host><trace proto="icmp"><hop ttl="1" ipaddr="192.168.1.1" rtt="1"/></trace></host></nmaprun>`
	hops, err := parseNmapTraceroute([]byte(xml), "192.168.1.55")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(hops) != 2 || hops[1].IP != "192.168.1.55" {
		t.Fatalf("want gateway+target, got %+v", hops)
	}
}

func TestParseNmapServiceOSType(t *testing.T) {
	xml := `<nmaprun><host><ports><port protocol="tcp" portid="22">
 <state state="open"/>
 <service name="ssh" product="OpenSSH" version="9.6" ostype="Linux" method="probed" conf="10"/>
</port></ports></host></nmaprun>`
	svc, err := parseNmapService([]byte(xml), 22)
	if err != nil || svc == nil {
		t.Fatalf("parse: %v %+v", err, svc)
	}
	if svc.OSType != "Linux" {
		t.Errorf("OSType = %q, want Linux", svc.OSType)
	}
}

func TestGatewayOf(t *testing.T) {
	cases := map[string]string{
		"192.168.1.55":   "192.168.1.1",
		"10.0.0.3":       "10.0.0.1",
		"192.168.1.1":    "", // target IS the gateway
		"192.168.1.0/24": "192.168.1.1",
		"not-an-ip":      "",
	}
	for in, want := range cases {
		if got := GatewayOf(in); got != want {
			t.Errorf("GatewayOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPortListArgCompressesRanges(t *testing.T) {
	ports := make([]int, 0, 1000)
	for p := 1; p <= 1000; p++ {
		ports = append(ports, p)
	}
	if got := portListArg(ports); got != "1-1000" {
		t.Errorf("contiguous range should compress to 1-1000, got %q", got)
	}
	if got := portListArg([]int{22, 80, 443, 8080}); got != "22,80,443,8080" {
		t.Errorf("sparse ports = %q", got)
	}
	if got := portListArg([]int{9, 8, 8, 70000, 0}); got != "8-9" {
		t.Errorf("dedupe+bounds = %q", got)
	}
}

func TestPortSpecArgs(t *testing.T) {
	if got := portSpecArgs(nil, nil); len(got) != 2 || got[0] != "--top-ports" {
		t.Errorf("nil cfg default = %v", got)
	}
	full := &domain.ScanConfig{FullTCPPorts: true}
	if got := portSpecArgs(nil, full); got[0] != "-p-" {
		t.Errorf("full = %v", got)
	}
	top := &domain.ScanConfig{TopTCPPorts: 1000}
	if got := portSpecArgs(nil, top); got[0] != "--top-ports" || got[1] != "1000" {
		t.Errorf("top = %v", got)
	}
	if got := portSpecArgs([]int{80, 443}, top); got[0] != "-p" {
		t.Errorf("explicit list wins = %v", got)
	}
}

func TestParseNmapOSDeviceType(t *testing.T) {
	xmlData := `<?xml version="1.0"?><nmaprun>
<host>
  <status state="up"/>
  <os>
    <osmatch name="Cisco IOS 15.1" accuracy="98">
      <osclass type="router" vendor="Cisco" osfamily="Cisco IOS" gen="router"/>
    </osmatch>
  </os>
</host>
</nmaprun>`
	res, err := parseNmapOS([]byte(xmlData))
	if err != nil || res == nil {
		t.Fatalf("parseNmapOS: %v %v", res, err)
	}
	if res.Device != "router" {
		t.Errorf("device = %q, want router", res.Device)
	}
	if res.Family != "cisco ios" {
		t.Errorf("family = %q", res.Family)
	}
	if res.Name != "Cisco IOS 15.1" {
		t.Errorf("name = %q", res.Name)
	}
}

func TestDeviceTypeFromNmap(t *testing.T) {
	cases := map[string]string{
		"general purpose":  "workstation",
		"WAP":              "access_point",
		"printer":          "printer",
		"media device":     "iot",
		"VoIP phone":       "mobile",
		"PDA":              "mobile",
		"storage-misc":     "nas",
		"broadband router": "router",
		"switch":           "switch",
		"camera":           "camera",
		"":                 "",
		"martian ship":     "",
	}
	for in, want := range cases {
		if got := deviceTypeFromNmap(in); got != want {
			t.Errorf("deviceTypeFromNmap(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLastOctet(t *testing.T) {
	if got := lastOctet("192.168.10.12"); got != 12 {
		t.Errorf("lastOctet = %d, want 12", got)
	}
	if got := lastOctet("10.0.0.3/24"); got != 3 {
		t.Errorf("lastOctet with prefix = %d, want 3", got)
	}
	if got := lastOctet("not-an-ip"); got != 0 {
		t.Errorf("lastOctet garbage = %d, want 0", got)
	}
}

func TestParseNmapDiscoveryMACVendor(t *testing.T) {
	// v1.14 regression: nmap's resolved OUI vendor string was dropped (only
	// the device-type hint survived) so the inventory could never show the
	// hardware vendor behind a MAC address.
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host starttime="1">
 <status state="up" reason="arp-response"/>
 <address addr="192.168.1.55" addrtype="ipv4"/>
 <address addr="B8:27:EB:11:22:33" addrtype="mac" vendor="Raspberry Pi Foundation"/>
</host>
</nmaprun>`
	hosts, err := parseNmapDiscovery([]byte(xml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("want 1 host, got %d", len(hosts))
	}
	h := hosts[0]
	if h.MAC != "B8:27:EB:11:22:33" {
		t.Errorf("MAC = %q", h.MAC)
	}
	if h.MACVendor != "Raspberry Pi Foundation" {
		t.Errorf("MACVendor = %q, want the nmap OUI string", h.MACVendor)
	}
	if h.Device != "iot" {
		t.Errorf("device hint = %q, want iot", h.Device)
	}
}

func TestParseNmapOSCapturesMAC(t *testing.T) {
	// The -O run's address records carry the MAC for hosts whose discovery
	// pass missed it; the parser must surface it on OSResult.
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host starttime="1">
 <status state="up" reason="reset"/>
 <address addr="10.0.0.7" addrtype="ipv4"/>
 <address addr="00:50:56:AA:BB:CC" addrtype="mac" vendor="VMware, Inc."/>
 <os><osmatch name="Linux 5.4" accuracy="98"><osclass type="general purpose" osfamily="linux" gen="linux" vendor="linux"/></osmatch></os>
</host>
</nmaprun>`
	res, err := parseNmapOS([]byte(xml))
	if err != nil || res == nil {
		t.Fatalf("parse: %v %+v", err, res)
	}
	if res.MAC != "00:50:56:AA:BB:CC" {
		t.Errorf("MAC = %q", res.MAC)
	}
	if res.MACVendor != "VMware, Inc." {
		t.Errorf("MACVendor = %q", res.MACVendor)
	}
	if res.Family != "linux" {
		t.Errorf("Family = %q", res.Family)
	}
}
