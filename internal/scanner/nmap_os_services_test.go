package scanner

import (
	"testing"
)

// parseNmapOS must pick the HIGHEST-accuracy match (accuracy ordering has
// drifted between nmap versions — taking the first line silently downgraded
// good fingerprints) and fall back to bare osclass data when --osscan-guess
// yields no confident match.
func TestParseNmapOSBestMatch(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun>
<host>
 <status state="up"/>
 <os>
  <osmatch name="Linux 2.6.9 - 2.6.33" accuracy="95">
   <osclass type="general purpose" vendor="Linux" osfamily="Linux" gen="2.6.x"/>
  </osmatch>
  <osmatch name="Linux 5.4" accuracy="100">
   <osclass type="server" vendor="Linux" osfamily="Linux" gen="5.x"/>
  </osmatch>
 </os>
</host>
</nmaprun>`
	res, err := parseNmapOS([]byte(xml))
	if err != nil || res == nil {
		t.Fatalf("parse = %v, %v", res, err)
	}
	if res.Name != "Linux 5.4" || res.Confidence != 1.0 {
		t.Errorf("match = %+v, want Linux 5.4 @1.0", res)
	}
	if res.Device != "server" {
		t.Errorf("device = %q, want server", res.Device)
	}
}

func TestParseNmapOSBareClass(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun>
<host>
 <status state="up"/>
 <os>
  <osclass type="wap" vendor="Ubiquiti" osfamily="Linux" gen="2.6.x"/>
 </os>
</host>
</nmaprun>`
	res, err := parseNmapOS([]byte(xml))
	if err != nil || res == nil {
		t.Fatalf("parse = %v, %v", res, err)
	}
	if res.Name != "" || res.Family != "linux" || res.Device != "access_point" || res.Confidence != 0.5 {
		t.Errorf("bare osclass = %+v, want family linux / access_point @0.5", res)
	}
}

// No <os> block at all (unprivileged run, host down) → nil, not an error.
func TestParseNmapOSEmpty(t *testing.T) {
	xml := `<?xml version="1.0"?><nmaprun><host><status state="down"/></host></nmaprun>`
	res, err := parseNmapOS([]byte(xml))
	if res != nil || err != nil {
		t.Errorf("parse = %v, %v; want nil,nil", res, err)
	}
}

// The batched --version-light pass feeds the fingerprint profile: every
// fingerprinted open port must come back with its service table row intact
// (product/version/ostype/CPEs), closed/unfingerprinted ports skipped.
func TestParseNmapServices(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun>
<host>
 <status state="up"/>
 <ports>
  <port protocol="tcp" portid="22">
   <state state="open"/>
   <service name="ssh" product="OpenSSH" version="10.0p2" ostype="linux" method="probed" conf="10">
    <cpe>cpe:/a:openbsd:openssh:10.0p2</cpe><cpe>cpe:/o:linux:linux_kernel</cpe>
   </service>
  </port>
  <port protocol="tcp" portid="80">
   <state state="open"/>
   <service name="http" method="table" conf="3"/>
  </port>
  <port protocol="tcp" portid="443">
   <state state="closed"/>
   <service name="https" method="table" conf="3"/>
  </port>
 </ports>
</host>
</nmaprun>`
	out := parseNmapServices([]byte(xml))
	if len(out) != 2 {
		t.Fatalf("want 2 services (port 80 has no fingerprint info, 443 closed), got %d: %+v", len(out), out)
	}
	if out[0].Name != "ssh" || out[0].Product != "OpenSSH" || out[0].OSType != "linux" {
		t.Errorf("service0 = %+v", out[0])
	}
	if out[0].CPE != "cpe:/a:openbsd:openssh:10.0p2" || len(out[0].CPEs) != 2 {
		t.Errorf("service0 cpes = %q, %v", out[0].CPE, out[0].CPEs)
	}
	// conf=10 maps to the lite ceiling (0.9), table-level conf=3 to the floor.
	if out[0].Confidence != 0.9 || out[1].Confidence != 0.5 {
		t.Errorf("confidence = %v, %v; want 0.9, 0.5", out[0].Confidence, out[1].Confidence)
	}
	if out[1].Product != "" {
		t.Errorf("table-only service must not claim a product: %+v", out[1])
	}
}
