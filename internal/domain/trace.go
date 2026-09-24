package domain

import "time"

// TraceHop is one parsed hop of a stored trace path. TTL is the hop's
// position on the route; unresponsive TTLs are simply absent (the scanner
// never invents intermediate addresses).
type TraceHop struct {
	TTL      int     `json:"ttl"`
	IP       string  `json:"ip"`
	Hostname string  `json:"hostname,omitempty"`
	RTTms    float64 `json:"rtt_ms,omitempty"`
}

// AssetTrace is the persisted result of one traceroute run against a target
// address: the parsed path (for the "from -> to" view), the probe that
// produced it (nmap probe family, tracert, tracepath, simulated) and the RAW
// engine output (nmap XML / tracert text) for auditing. One row per
// (site, target): a fresh scan refreshes the path instead of accumulating
// history — the observations table already keeps the full history.
// hop_ips carries every address on the path so an asset page can list all
// traces that COVER its address, not only traces aimed at it.
type AssetTrace struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	SiteID         string     `json:"site_id"`
	ScanID         string     `json:"scan_id"`
	TargetIP       string     `json:"target_ip"`
	Method         string     `json:"method"` // traceroute | gateway-l2 | gateway-guess
	Probe          string     `json:"probe"`  // tcp-syn | udp | icmp | tcp-connect | tracert | tracepath | simulated
	Complete       bool       `json:"complete"`
	HopsCount      int        `json:"hops_count"`
	Path           []TraceHop `json:"path"`
	HopIPs         []string   `json:"hop_ips"`
	Raw            string     `json:"raw,omitempty"`
	Confidence     Confidence `json:"confidence"`
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
}
