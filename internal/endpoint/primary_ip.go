// Primary-address selection: which of the endpoint's own addresses is the
// one it is actually reachable on. The management connection to the hub is
// the ground truth — its source address is the address the rest of the
// network sees for this device — and a deterministic interface scan is the
// fallback when that cannot be determined.

package endpoint

import (
	"net"
	"strings"
	"time"

	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
)

// PickPrimaryIP returns the endpoint's management-facing address:
// the source address of a (packetless) UDP "connection" toward the hub,
// else the first usable IPv4 of an UP interface with a MAC, else the first
// usable IPv4 of any interface, else the first usable IPv6. Loopback,
// link-local and unspecified addresses never qualify. Interface addresses
// are normalized (prefix length and zone stripped) so raw system forms
// like "192.168.1.80/24" qualify too. Empty when the host has no usable
// address at all.
func PickPrimaryIP(target string, ifaces []*agentv1.Iface) string {
	if ip := outboundIP(target); ip != "" {
		return ip
	}
	usable := func(addr string) bool { return isReportableAddr(addr) }
	// Real NICs first: an UP interface that carries a MAC is physical or
	// virtual hardware with a LAN identity — bridges/tunnels usually have
	// neither or come later alphabetically.
	for _, f := range ifaces {
		if f.GetStatus() != "up" || f.GetMac() == "" {
			continue
		}
		for _, a := range f.GetIps() {
			if ip := normalizeIfaceAddr(a); isIPv4(ip) && usable(ip) {
				return ip
			}
		}
	}
	for _, f := range ifaces {
		for _, a := range f.GetIps() {
			if ip := normalizeIfaceAddr(a); isIPv4(ip) && usable(ip) {
				return ip
			}
		}
	}
	for _, f := range ifaces {
		for _, a := range f.GetIps() {
			if ip := normalizeIfaceAddr(a); !isIPv4(ip) && ip != "" && usable(ip) {
				return stripZone(ip)
			}
		}
	}
	return ""
}

// outboundIP asks the kernel which local address routes to the hub. UDP
// connect sends no packets — it only consults the routing table. Loopback
// results (hub on the same host) are rejected so the report carries a
// LAN-visible address; the interface scan fallback covers that case.
func outboundIP(target string) string {
	if target == "" {
		return ""
	}
	conn, err := net.DialTimeout("udp", target, 3*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	udp, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || udp.IP == nil {
		return ""
	}
	if udp.IP.IsLoopback() || udp.IP.IsUnspecified() || udp.IP.IsLinkLocalUnicast() {
		return ""
	}
	return udp.IP.String()
}

// isReportableAddr filters addresses that identify nothing on the network:
// loopback, link-local (IPv4 169.254/16, IPv6 fe80::/10) and the unspecified
// address. IPv6 zone suffixes ("%eth0") are handled by the caller.
func isReportableAddr(addr string) bool {
	ip := net.ParseIP(stripZone(addr))
	if ip == nil {
		return false
	}
	return !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast()
}

func isIPv4(addr string) bool {
	return net.ParseIP(stripZone(addr)) != nil &&
		net.ParseIP(stripZone(addr)).To4() != nil
}

func stripZone(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Not host:port — strip a trailing IPv6 zone ("%eth0") if present.
		if i := strings.LastIndexByte(addr, '%'); i >= 0 {
			return addr[:i]
		}
		return addr
	}
	return host
}
