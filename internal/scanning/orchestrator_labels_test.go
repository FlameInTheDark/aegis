package scanning

import (
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// Device hints from service fingerprints must stay narrow: a wrong device
// label erodes trust in the whole inventory. CUPS in particular runs on
// ordinary workstations that merely share a printer — it must not flip the
// asset to "printer".
func TestDeviceHintFromService(t *testing.T) {
	cases := []struct {
		name, product string
		cpes          []string
		want          string
	}{
		{name: "jetdirect", want: "printer"},
		{name: "ipp", product: "HP JetDirect L11", want: "printer"},
		{name: "http", product: "HP LaserJet M404", want: "printer"},
		{name: "printer", want: "printer"},
		{name: "rtsp", want: "camera"},
		{name: "rtsp", product: "IP Camera RTSP", want: "camera"},
		{name: "http", product: "Hikvision-Webs", want: "camera"},
		{name: "http", product: "Synology DiskStation", want: "nas"},
		{name: "http", product: "QNAP Turbo NAS", want: "nas"},
		// Must NOT hint: generic web/app servers and CUPS on a workstation.
		{name: "http", product: "nginx"},
		{name: "http", product: "Apache Tomcat"},
		{name: "ipp", product: "CUPS IPP"},
		{name: "ssh", product: "OpenSSH"},
		{name: "", product: ""},
		// Hardware CPEs carry the strongest signal.
		{cpes: []string{"cpe:/h:hp:laserjet:L11"}, want: "printer"},
		{cpes: []string{"cpe:2.3:h:genericcam:ip_camera:2.1:*:*:*:*:*:*:*"}, want: "camera"},
		{cpes: []string{"cpe:/h:synology:diskstation:3"}, want: "nas"},
		// Application/OS CPEs must never hint a device class.
		{cpes: []string{"cpe:/a:openbsd:openssh:10.0p2", "cpe:/o:linux:linux_kernel"}},
	}
	for _, c := range cases {
		if got := deviceHintFromService(c.name, c.product, c.cpes); got != c.want {
			t.Errorf("deviceHintFromService(%q, %q, %v) = %q, want %q", c.name, c.product, c.cpes, got, c.want)
		}
	}
}

// "Unknown Device · 192.168.1.5" hid the one fact the operator cares about
// behind a classification we don't have. Unidentified nodes must be named
// by address; identified device classes keep the "Class · IP" form.
func TestNodeLabel(t *testing.T) {
	cases := []struct {
		name string
		a    *domain.Asset
		ip   string
		want string
	}{
		{"nil asset falls back to ip", nil, "10.0.0.9", "10.0.0.9"},
		{"hostname wins", &domain.Asset{Hostname: "nas-01"}, "10.0.0.9", "nas-01"},
		{"identified device gets class + address", &domain.Asset{DeviceType: domain.DeviceRouter}, "192.168.1.1", "Router · 192.168.1.1"},
		{"identified device with primary ip", &domain.Asset{DeviceType: domain.DeviceMobile, PrimaryIP: "10.0.0.12"}, "", "Phone · 10.0.0.12"},
		{"unidentified device shows the address", &domain.Asset{DeviceType: domain.DeviceUnknown}, "192.168.1.5", "192.168.1.5"},
		{"empty device type shows the address", &domain.Asset{DeviceType: ""}, "192.168.1.5", "192.168.1.5"},
		{"nothing known but id", &domain.Asset{DeviceType: domain.DeviceUnknown, ID: "b1e5f00d-1234-5678-9abc-def012345678"}, "", "Host b1e5f00d"},
	}
	for _, c := range cases {
		if got := nodeLabel(c.a, c.ip); got != c.want {
			t.Errorf("%s: nodeLabel() = %q, want %q", c.name, got, c.want)
		}
	}
}
