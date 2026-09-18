package scanner

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// nmapRun is the subset of nmap XML output (-oX -) that we consume.
// Parsing is deliberately tolerant: scanner output is untrusted input
// (§146) — malformed fields become empty strings, never errors.
type nmapOSClass struct {
	Type   string `xml:"type,attr"`
	Vendor string `xml:"vendor,attr"`
	Family string `xml:"osfamily,attr"`
	Gen    string `xml:"gen,attr"`
}

type nmapRun struct {
	Hosts    []nmapHost `xml:"host"`
	RunStats struct {
		Finished struct {
			Elapsed string `xml:"elapsed,attr"`
			Summary string `xml:"summary,attr"`
			Exit    string `xml:"exit,attr"`
		} `xml:"finished"`
	} `xml:"runstats"`
}

type nmapHost struct {
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
		Vendor   string `xml:"vendor,attr"`
	} `xml:"address"`
	Hostnames struct {
		Hostname []struct {
			Name string `xml:"name,attr"`
			Type string `xml:"type,attr"`
		} `xml:"hostname"`
	} `xml:"hostnames"`
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Ports struct {
		Port []struct {
			Protocol string `xml:"protocol,attr"`
			PortID   int    `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name       string   `xml:"name,attr"`
				Product    string   `xml:"product,attr"`
				Version    string   `xml:"version,attr"`
				Vendor     string   `xml:"vendor,attr"`
				Method     string   `xml:"method,attr"`
				Confidence string   `xml:"conf,attr"`
				OSType     string   `xml:"ostype,attr"`
				CPE        []string `xml:"cpe"`
			} `xml:"service"`
		} `xml:"port"`
	} `xml:"ports"`
	OS struct {
		OSMatch []struct {
			Name     string        `xml:"name,attr"`
			Accuracy int           `xml:"accuracy,attr"`
			OSClass  []nmapOSClass `xml:"osclass"`
		} `xml:"osmatch"`
		// Bare osclass elements (--osscan-guess on hosts with no confident
		// match) appear directly under <os> on some nmap versions.
		OSClass []nmapOSClass `xml:"osclass"`
	} `xml:"os"`
	Trace struct {
		Port  int    `xml:"port,attr"`
		Proto string `xml:"proto,attr"`
		Hops  []struct {
			TTL   int     `xml:"ttl,attr"`
			IP    string  `xml:"ipaddr,attr"`
			Host  string  `xml:"host,attr"`
			RTTms float64 `xml:"rtt,attr"`
		} `xml:"hop"`
	} `xml:"trace"`
}

// parseNmapDiscovery parses `nmap -sn -oX -` output.
func parseNmapDiscovery(data []byte) ([]HostResult, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("nmap xml: %w", err)
	}
	var out []HostResult
	for _, h := range run.Hosts {
		if h.Status.State != "up" {
			continue
		}
		hr := HostResult{Confidence: 0.85}
		for _, a := range h.Addresses {
			switch a.AddrType {
			case "ipv4", "ipv6":
				hr.IP = a.Addr
			case "mac":
				hr.MAC = a.Addr
				if a.Vendor != "" {
					hr.Device = deviceHintFromVendor(a.Vendor)
				}
			}
		}
		for _, hn := range h.Hostnames.Hostname {
			if hn.Type == "PTR" || hr.Hostname == "" {
				hr.Hostname = hn.Name
			}
		}
		if hr.IP != "" {
			out = append(out, hr)
		}
	}
	return out, nil
}

// parseNmapPorts parses `nmap -sS -oX -` output.
func parseNmapPorts(data []byte) ([]PortResult, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("nmap xml: %w", err)
	}
	var out []PortResult
	for _, h := range run.Hosts {
		for _, p := range h.Ports.Port {
			if p.State.State != "open" {
				continue
			}
			out = append(out, PortResult{
				Port:     p.PortID,
				Protocol: p.Protocol,
				Service:  p.Service.Name,
				State:    "open",
			})
		}
	}
	return out, nil
}

// parseNmapService parses `nmap -sV -p N -oX -` for a single host/port.
func parseNmapService(data []byte, port int) (*ServiceResult, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("nmap xml: %w", err)
	}
	for _, h := range run.Hosts {
		for _, p := range h.Ports.Port {
			if p.PortID != port {
				continue
			}
			conf := 0.6
			if c := strings.TrimSpace(p.Service.Confidence); c == "10" {
				conf = 0.95
			} else if c == "8" || c == "9" {
				conf = 0.85
			}
			res := &ServiceResult{
				Port:       p.PortID,
				Protocol:   p.Protocol,
				Name:       p.Service.Name,
				Product:    p.Service.Product,
				Vendor:     p.Service.Vendor,
				Version:    p.Service.Version,
				OSType:     p.Service.OSType,
				Confidence: conf,
				CPEs:       append([]string(nil), p.Service.CPE...),
			}
			if len(p.Service.CPE) > 0 {
				res.CPE = p.Service.CPE[0]
			}
			if res.Name == "" && res.Product == "" {
				return nil, nil // no useful fingerprint produced
			}
			return res, nil
		}
	}
	return nil, nil
}

// parseNmapOS parses `nmap -O -oX -` output. Alongside the OS fingerprint it
// extracts nmap's device classification (osclass@type: "router", "WAP",
// "printer", "media device", "general purpose", ...) and maps it to the
// platform device taxonomy. nmap lists matches best-first, but the parser
// picks the highest-accuracy match explicitly — accuracy ordering has
// drifted between nmap versions, and taking the first line silently
// downgraded otherwise-good fingerprints. When no osmatch exists at all
// (--osscan-guess on a hard host), bare osclass data still yields a family
// with a conservative 0.5 confidence instead of nothing.
func parseNmapOS(data []byte) (*OSResult, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("nmap xml: %w", err)
	}
	for _, h := range run.Hosts {
		best := -1
		for i, m := range h.OS.OSMatch {
			if best < 0 || m.Accuracy > h.OS.OSMatch[best].Accuracy {
				best = i
			}
		}
		if best >= 0 {
			m := h.OS.OSMatch[best]
			res := &OSResult{Name: m.Name, Confidence: float64(m.Accuracy) / 100}
			for _, c := range m.OSClass {
				if res.Family == "" {
					res.Family = strings.ToLower(c.Family)
				}
				if res.Device == "" {
					res.Device = deviceTypeFromNmap(c.Type)
				}
				if res.Family != "" && res.Device != "" {
					break
				}
			}
			return res, nil
		}
		if len(h.OS.OSClass) > 0 {
			c := h.OS.OSClass[0]
			return &OSResult{
				Family:     strings.ToLower(c.Family),
				Device:     deviceTypeFromNmap(c.Type),
				Confidence: 0.5,
			}, nil
		}
	}
	return nil, nil
}

// parseNmapServices parses a batched `nmap -sV -oX -` run (FingerprintServicesLite)
// and returns every port nmap could fingerprint — the per-port variant (parseNmapService)
// only looks at one. Ports without any service info are skipped.
func parseNmapServices(data []byte) []ServiceResult {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil
	}
	var out []ServiceResult
	for _, h := range run.Hosts {
		for _, p := range h.Ports.Port {
			if p.State.State != "open" {
				continue
			}
			if p.Service.Name == "" && p.Service.Product == "" {
				continue // no fingerprint produced for this port
			}
			conf := 0.5 // --version-light is intentionally weaker than intensity 5
			if c := strings.TrimSpace(p.Service.Confidence); c == "10" {
				conf = 0.9
			} else if c == "8" || c == "9" {
				conf = 0.8
			}
			res := ServiceResult{
				Port:       p.PortID,
				Protocol:   p.Protocol,
				Name:       p.Service.Name,
				Product:    p.Service.Product,
				Vendor:     p.Service.Vendor,
				Version:    p.Service.Version,
				OSType:     p.Service.OSType,
				Confidence: conf,
				CPEs:       append([]string(nil), p.Service.CPE...),
			}
			if len(p.Service.CPE) > 0 {
				res.CPE = p.Service.CPE[0]
			}
			out = append(out, res)
		}
	}
	return out
}

// deviceTypeFromNmap maps nmap osclass@type values to the platform device
// taxonomy. Unknown/empty input maps to "" (no claim — the asset stays
// "unknown" instead of being misclassified).
func deviceTypeFromNmap(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "general purpose", "desktop", "workstation":
		return "workstation"
	case "router", "broadband router", "wireless router":
		return "router"
	case "switch", "hub":
		return "switch"
	case "firewall", "security", "load balancer":
		return "firewall"
	case "wap", "access point", "wireless access point":
		return "access_point"
	case "printer", "print server":
		return "printer"
	case "media device", "av", "streaming":
		return "iot"
	case "storage-misc", "nas", "file server":
		return "nas"
	case "pda", "phone", "smartphone", "voip phone", "voip adapter", "mobile":
		return "mobile"
	case "camera", "webcam", "surveillance":
		return "camera"
	case "game console", "console":
		return "iot"
	case "special purpose", "embedded", "single-board computer":
		return "iot"
	case "power device", "ups", "pdu":
		return "iot"
	case "virtual machine", "hypervisor":
		return "virtual_machine"
	case "server":
		return "server"
	default:
		return ""
	}
}

// parseNmapTraceroute parses `nmap -sn --traceroute -oX -` output for a
// single target. The final hop is always the target itself, even when nmap
// reports no explicit final hop element (directly connected targets).
func parseNmapTraceroute(data []byte, target string) ([]Hop, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("nmap xml: %w", err)
	}
	for _, h := range run.Hosts {
		if len(h.Trace.Hops) == 0 {
			continue
		}
		var out []Hop
		for _, hop := range h.Trace.Hops {
			if hop.IP == "" {
				continue // TTL timeout: no responder
			}
			out = append(out, Hop{TTL: hop.TTL, IP: hop.IP, Hostname: hop.Host, RTTms: hop.RTTms})
		}
		if len(out) > 0 {
			if last := out[len(out)-1]; last.IP != target {
				out = append(out, Hop{TTL: last.TTL + 1, IP: target})
			}
			return out, nil
		}
	}
	return nil, nil
}

// deviceHintFromVendor maps MAC OUI vendor strings to device type hints.
func deviceHintFromVendor(vendor string) string {
	v := strings.ToLower(vendor)
	switch {
	case strings.Contains(v, "vmware"), strings.Contains(v, "qemu"), strings.Contains(v, "kvm"):
		return "virtual_machine"
	case strings.Contains(v, "raspberry"):
		return "iot"
	case strings.Contains(v, "cisco"), strings.Contains(v, "ubiquiti"):
		return "router"
	case strings.Contains(v, "apple"):
		return "workstation"
	case strings.Contains(v, "intel"), strings.Contains(v, "realtek"), strings.Contains(v, "supermicro"):
		return "server"
	case strings.Contains(v, "philips"), strings.Contains(v, "amazon"):
		return "iot"
	default:
		return ""
	}
}
