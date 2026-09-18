// Package domain defines the platform's core business objects.
// Domain types are independent of HTTP, gRPC and storage concerns.
package domain

import (
	"time"
)

// Severity of a vulnerability or detection.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ValidSeverities is the ordered (lowest→highest) severity ladder.
var ValidSeverities = []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// Rank converts a severity to a numeric rank (informational=0 … critical=4).
func (s Severity) Rank() int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}

// Confidence expresses how certain a fingerprint / observation is (0..1).
// Uncertain evidence must never be presented as fact (see docs/security-model.md).
type Confidence float64

// Source identifies where an observation came from.
type Source string

const (
	SourceNmap          Source = "nmap"
	SourceZgrab         Source = "zgrab2"
	SourceNuclei        Source = "nuclei"
	SourceMasscan       Source = "masscan"
	SourceAgent         Source = "endpoint_agent"
	SourceSNMP          Source = "snmp"
	SourceSuricata      Source = "suricata"
	SourceZeek          Source = "zeek"
	SourceSnort         Source = "snort"
	SourceSimulated     Source = "simulated"
	SourceManual        Source = "manual"
	SourceFeed          Source = "feed"
	SourceHeuristic     Source = "heuristic"
	SourceBanner        Source = "banner"
	SourceTLS           Source = "tls"
	SourceHTTP          Source = "http"
	SourceARP           Source = "arp"
	SourceNDP           Source = "ndp"
	SourceDNS           Source = "dns"
	SourceDHCP          Source = "dhcp"
	SourceLLDP          Source = "lldp"
	SourceCDP           Source = "cdp"
	SourceMacVendor     Source = "mac_vendor"
	SourceRoutingTable  Source = "routing_table"
	SourceFlowTelemetry Source = "flow_telemetry"
)

// Exposure describes network reachability of an asset or service.
type Exposure string

const (
	ExposureInternal Exposure = "internal_only"
	ExposureVPN      Exposure = "vpn_only"
	ExposurePublic   Exposure = "publicly_reachable"
	ExposureUnknown  Exposure = "unknown"
)

// Criticality is the user-assigned business importance of an asset.
type Criticality string

const (
	CriticalityLow      Criticality = "low"
	CriticalityMedium   Criticality = "medium"
	CriticalityHigh     Criticality = "high"
	CriticalityCritical Criticality = "critical"
)

// TimeRange is a closed-open interval used by filters and reports.
type TimeRange struct {
	From time.Time `json:"from,omitempty"`
	To   time.Time `json:"to,omitempty"`
}
