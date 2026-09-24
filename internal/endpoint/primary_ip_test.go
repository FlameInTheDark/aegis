// Primary-address selection: the management address toward the hub wins,
// and the fallback order over the reported interfaces is deterministic.

package endpoint

import (
	"net"
	"testing"

	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
)

func ifc(name, mac, status string, ips ...string) *agentv1.Iface {
	return &agentv1.Iface{Name: name, Mac: mac, Status: status, Ips: ips}
}

func TestPickPrimaryIPFallsBackToUpNICWithMAC(t *testing.T) {
	ifaces := []*agentv1.Iface{
		ifc("loopback", "", "up", "127.0.0.1", "::1"),
		ifc("tunnel0", "", "up", "10.8.0.2"), // no MAC: after real NICs
		ifc("Ethernet", "aa:bb:cc:dd:ee:ff", "up", "169.254.5.5", "192.168.1.20"),
		ifc("docker0", "02:42:00:00:00:01", "up", "172.17.0.1"),
		ifc("Wi-Fi", "11:22:33:44:55:66", "down", "192.168.1.99"),
	}
	// Empty target: the routing probe is skipped and the interface scan
	// decides. The fallback is deterministic — the first UP interface
	// carrying a MAC in report order (Windows/Linux enumerate the physical
	// NIC early), and within it the first usable address over link-local.
	if got := PickPrimaryIP("", ifaces); got != "192.168.1.20" {
		t.Fatalf("PickPrimaryIP = %q, want the LAN address of the first UP NIC with a MAC", got)
	}
}

func TestPickPrimaryIPUsesAnyUpIPv4WhenNoMAC(t *testing.T) {
	ifaces := []*agentv1.Iface{
		ifc("loopback", "", "up", "127.0.0.1"),
		ifc("ppp0", "", "up", "10.8.0.2"),
	}
	if got := PickPrimaryIP("", ifaces); got != "10.8.0.2" {
		t.Fatalf("PickPrimaryIP = %q, want the usable IPv4 of the UP interface", got)
	}
}

func TestPickPrimaryIPFallsBackToUsableIPv6(t *testing.T) {
	ifaces := []*agentv1.Iface{
		ifc("loopback", "", "up", "127.0.0.1", "::1"),
		ifc("eth0", "aa:bb:cc:dd:ee:ff", "up", "fe80::1%eth0", "2001:db8::5%eth0"),
	}
	if got := PickPrimaryIP("", ifaces); got != "2001:db8::5" {
		t.Fatalf("PickPrimaryIP = %q, want the global IPv6 without its zone suffix", got)
	}
}

func TestPickPrimaryIPIgnoresUnusableAddresses(t *testing.T) {
	ifaces := []*agentv1.Iface{
		ifc("eth0", "aa:bb:cc:dd:ee:ff", "up", "0.0.0.0", "169.254.1.2", "not-an-ip"),
		ifc("eth1", "aa:bb:cc:dd:ee:00", "up", "192.168.1.5"),
	}
	if got := PickPrimaryIP("", ifaces); got != "192.168.1.5" {
		t.Fatalf("PickPrimaryIP = %q, want the first interface with a usable address", got)
	}
}

func TestPickPrimaryIPRejectsLoopbackRoutingProbe(t *testing.T) {
	// A listening loopback socket makes the UDP probe succeed — and its
	// result (127.0.0.1) must be rejected so the report carries a
	// LAN-visible address from the interface scan instead.
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("udp loopback unavailable: %v", err)
	}
	defer ln.Close()
	ifaces := []*agentv1.Iface{ifc("Ethernet", "aa:bb:cc:dd:ee:ff", "up", "192.168.1.20")}
	if got := PickPrimaryIP(ln.LocalAddr().String(), ifaces); got != "192.168.1.20" {
		t.Fatalf("PickPrimaryIP = %q, want the interface address (loopback probe result rejected)", got)
	}
}

func TestPickPrimaryIPRefusedProbeFallsThrough(t *testing.T) {
	// Connection-refused on loopback fails the probe immediately — the
	// interface scan must still produce the LAN address.
	ifaces := []*agentv1.Iface{ifc("Ethernet", "aa:bb:cc:dd:ee:ff", "up", "192.168.1.20")}
	if got := PickPrimaryIP("127.0.0.1:1", ifaces); got != "192.168.1.20" {
		t.Fatalf("PickPrimaryIP = %q, want the interface address", got)
	}
}

func TestPickPrimaryIPNoUsableAddress(t *testing.T) {
	ifaces := []*agentv1.Iface{ifc("loopback", "", "up", "127.0.0.1")}
	if got := PickPrimaryIP("", ifaces); got != "" {
		t.Fatalf("PickPrimaryIP = %q, want empty when only loopback exists", got)
	}
	if got := PickPrimaryIP("", nil); got != "" {
		t.Fatalf("PickPrimaryIP = %q, want empty without interfaces", got)
	}
}
