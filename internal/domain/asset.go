package domain

import (
	"fmt"
	"time"
)

// DeviceType classifies an asset.
type DeviceType string

const (
	DeviceWorkstation   DeviceType = "workstation"
	DeviceServer        DeviceType = "server"
	DeviceLaptop        DeviceType = "laptop"
	DeviceMobile        DeviceType = "mobile"
	DeviceRouter        DeviceType = "router"
	DeviceSwitch        DeviceType = "switch"
	DeviceFirewall      DeviceType = "firewall"
	DeviceAccessPoint   DeviceType = "access_point"
	DevicePrinter       DeviceType = "printer"
	DeviceCamera        DeviceType = "camera"
	DeviceNAS           DeviceType = "nas"
	DeviceHypervisor    DeviceType = "hypervisor"
	DeviceVM            DeviceType = "virtual_machine"
	DeviceContainerHost DeviceType = "container_host"
	DeviceIoT           DeviceType = "iot"
	DeviceUnknown       DeviceType = "unknown"
)

// Asset is a logical entity: one physical/virtual device at a site.
// Identity is never IP-based alone (RFC1918 reuse across sites).
type Asset struct {
	ID              string      `json:"id"`
	OrganizationID  string      `json:"organization_id"`
	SiteID          string      `json:"site_id"`
	Hostname        string      `json:"hostname,omitempty"`
	FQDN            string      `json:"fqdn,omitempty"`
	Vendor          string      `json:"vendor,omitempty"`
	Model           string      `json:"model,omitempty"`
	SerialNumber    string      `json:"serial_number,omitempty"`
	DeviceType      DeviceType  `json:"device_type"`
	OSFamily        string      `json:"os_family,omitempty"`
	OSName          string      `json:"os_name,omitempty"`
	OSVersion       string      `json:"os_version,omitempty"`
	KernelVersion   string      `json:"kernel_version,omitempty"`
	Architecture    string      `json:"architecture,omitempty"`
	OSConfidence    Confidence  `json:"os_confidence"`
	OSSources       []string    `json:"os_sources,omitempty"`
	DeviceTypeConf  Confidence  `json:"device_type_confidence"`
	DeviceTypeSrcs  []string    `json:"device_type_sources,omitempty"`
	Exposure        Exposure    `json:"exposure"`
	Criticality     Criticality `json:"criticality"`
	RiskScore       float64     `json:"risk_score"`
	RiskExplanation string      `json:"risk_explanation,omitempty"`
	HasAgent        bool        `json:"has_agent"`
	AgentID         *string     `json:"agent_id,omitempty"`
	Tags            []string    `json:"tags,omitempty"`
	Owner           string      `json:"owner,omitempty"`
	Notes           string      `json:"notes,omitempty"`
	FirstSeen       time.Time   `json:"first_seen"`
	LastSeen        time.Time   `json:"last_seen"`
	UpdatedAt       time.Time   `json:"updated_at"`
	// DemoSource marks records created by the demo/simulation seeder.
	DemoSource bool `json:"demo_source"`
	// PrimaryIP is the address the asset currently answers on (latest "ip"
	// identifier); used for human-friendly naming when no hostname exists.
	PrimaryIP string `json:"primary_ip,omitempty"`
	// Analyst overrides (migration 0031). Never written by scan ingestion:
	// the scanned hostname/device_type columns keep the detection data, and
	// clearing the override reveals it again. NULL = no override. The repo
	// read path applies these onto the effective Hostname/DeviceType, so
	// every consumer sees the corrected value while the JSON still carries
	// the override fields for the UI's "overridden" badge and reset action.
	NameOverride *string `json:"name_override,omitempty"`
	TypeOverride *string `json:"device_type_override,omitempty"`
	// ParentOverride pins this asset's topology parent to another asset
	// (by asset id, same organization). Transparent L2 switches never
	// show up as a routable hop, so traceroute wires the hosts behind
	// them straight to the router; the analyst uses this override to
	// state the real wiring. Like the identity overrides it is never
	// written by scan ingestion and NULL means "follow the evidence".
	// The topology view turns it into a confidence-1.0 parent edge that
	// beats any inferred link.
	ParentOverride *string `json:"parent_override,omitempty"`
}

// deviceTypeLabels maps the taxonomy to the short human names shown in the
// asset list and topology graph. "Unknown" is the honest default when no
// evidence supports a classification.
var deviceTypeLabels = map[DeviceType]string{
	DeviceWorkstation:   "Computer",
	DeviceServer:        "Server",
	DeviceLaptop:        "Laptop",
	DeviceMobile:        "Phone",
	DeviceRouter:        "Router",
	DeviceSwitch:        "Switch",
	DeviceFirewall:      "Firewall",
	DeviceAccessPoint:   "Access Point",
	DevicePrinter:       "Printer",
	DeviceCamera:        "Camera",
	DeviceNAS:           "NAS",
	DeviceHypervisor:    "Hypervisor",
	DeviceVM:            "Virtual Machine",
	DeviceContainerHost: "Container Host",
	DeviceIoT:           "IoT Device",
	DeviceUnknown:       "Unknown Device",
}

// Label returns the friendly device name for the type.
func (d DeviceType) Label() string {
	if l, ok := deviceTypeLabels[d]; ok {
		return l
	}
	return string(d)
}

// ValidDeviceType reports whether s is part of the device taxonomy. The
// asset-override endpoint allows exactly these values (plus clearing).
func ValidDeviceType(s string) bool {
	_, ok := deviceTypeLabels[DeviceType(s)]
	return ok
}

// ParentOverrideCycle reports whether pointing asset `self` at `proposed`
// as its topology parent would close a cycle through the EXISTING override
// chain (proposed's parent, its parent's parent, ...). The lookup returns
// the persisted ParentOverride of an asset id; a missing asset or a nil
// override simply ends the walk. It does not consider the proposed link's
// own effect on downstream assets — those re-parent only through future
// writes, each of which is checked the same way.
func ParentOverrideCycle(lookup func(id string) (*string, error), self, proposed string) (bool, error) {
	cur := proposed
	for hop := 0; hop <= maxOverrideChain; hop++ {
		if cur == self {
			return true, nil
		}
		next, err := lookup(cur)
		if err != nil || next == nil || *next == "" {
			return false, err
		}
		cur = *next
	}
	// A chain longer than the org could ever legitimately produce is treated
	// as corrupt rather than walked forever.
	return false, fmt.Errorf("parent override chain exceeds %d hops", maxOverrideChain)
}

const maxOverrideChain = 32

// Identifier is a strong/medium/weak identity datum attached to an asset
// used by the correlation engine to merge duplicate discoveries.
type Identifier struct {
	AssetID string
	Type    string // agent_id|certificate|mac|serial|machine_id|cloud_instance|hostname|fqdn|ssh_hostkey|smb_name|ip
	Value   string
	Weight  float64 // strong=1.0, medium=0.6, weak=0.2
}

// IdentifierWeights defines correlation weights by identifier type.
var IdentifierWeights = map[string]float64{
	"agent_id":       1.0,
	"certificate":    1.0,
	"serial":         0.95,
	"machine_id":     0.95,
	"cloud_instance": 0.95,
	"mac":            0.9,
	"ssh_hostkey":    0.8,
	"smb_name":       0.7,
	"hostname":       0.6,
	"fqdn":           0.6,
	"ip":             0.2,
}

// PrimaryIPWeight is the weight of an endpoint-reported management address
// ("ip" identifier): the device states which of its addresses talks to the
// hub, and the asset read path picks the highest-weighted address as the
// asset's primary IP. Above plain "ip" (0.2), below hostname (0.6).
const PrimaryIPWeight = 0.3

// Interface is a network interface of an asset.
type Interface struct {
	ID        string          `json:"id"`
	AssetID   string          `json:"asset_id"`
	MAC       string          `json:"mac,omitempty"`
	Vendor    string          `json:"vendor,omitempty"` // OUI organization (nmap)
	Name      string          `json:"name,omitempty"`   // eth0, en0, ...
	VLANID    *int            `json:"vlan_id,omitempty"`
	MTU       int             `json:"mtu,omitempty"`
	SpeedMbps int             `json:"speed_mbps,omitempty"`
	Status    string          `json:"status,omitempty"` // up|down|unknown
	FirstSeen time.Time       `json:"first_seen"`
	LastSeen  time.Time       `json:"last_seen"`
	Addresses []IPObservation `json:"addresses,omitempty"`
}

// IPObservation is an address bound to an interface at a point in time.
// Historical observations are kept so IP reassignment is representable.
type IPObservation struct {
	IP        string    `json:"ip"`
	IsPrimary bool      `json:"is_primary,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Service is an observed service endpoint on an asset.
type Service struct {
	ID              string     `json:"id"`
	AssetID         string     `json:"asset_id"`
	OrganizationID  string     `json:"organization_id"`
	Protocol        string     `json:"protocol"` // tcp|udp
	Port            int        `json:"port"`
	ServiceName     string     `json:"service_name,omitempty"` // https, ssh...
	Product         string     `json:"product,omitempty"`
	Vendor          string     `json:"vendor,omitempty"`
	DetectedVersion string     `json:"detected_version,omitempty"`
	VersionNorm     string     `json:"version_norm,omitempty"`
	VersionRange    string     `json:"version_range,omitempty"`
	VersionConf     Confidence `json:"version_confidence"`
	CPEs            []string   `json:"cpes,omitempty"`
	Banner          string     `json:"banner,omitempty"` // attacker-controlled text; redact/escape
	TLS             *TLSInfo   `json:"tls,omitempty"`
	HTTP            *HTTPInfo  `json:"http,omitempty"`
	Sources         []string   `json:"sources,omitempty"`
	Confidence      Confidence `json:"confidence"`
	Exposure        Exposure   `json:"exposure"`
	Flags           []string   `json:"flags,omitempty"` // unexpected_port|admin_exposed|legacy_protocol|unencrypted|database
	FirstSeen       time.Time  `json:"first_seen"`
	LastSeen        time.Time  `json:"last_seen"`
	State           string     `json:"state"` // open|closed|filtered
}

func (s Service) Endpoint() string {
	return fmt.Sprintf("%s://%s:%d", s.Protocol, s.AssetID, s.Port)
}

// TLSInfo holds certificate/TLS metadata collected by zgrab2 or the agent.
type TLSInfo struct {
	Version    string     `json:"version,omitempty"`
	Cipher     string     `json:"cipher,omitempty"`
	SubjectCN  string     `json:"subject_cn,omitempty"`
	Issuer     string     `json:"issuer,omitempty"`
	NotBefore  *time.Time `json:"not_before,omitempty"`
	NotAfter   *time.Time `json:"not_after,omitempty"`
	SHA256     string     `json:"sha256,omitempty"`
	SANs       []string   `json:"sans,omitempty"`
	SelfSigned bool       `json:"self_signed,omitempty"`
	Expired    bool       `json:"expired,omitempty"`
	ALPN       []string   `json:"alpn,omitempty"`
}

// HTTPInfo holds application-layer HTTP metadata.
type HTTPInfo struct {
	Title         string   `json:"title,omitempty"`
	ServerHeader  string   `json:"server_header,omitempty"`
	PoweredBy     string   `json:"x_powered_by,omitempty"`
	StatusLine    string   `json:"status_line,omitempty"`
	Methods       []string `json:"methods,omitempty"`
	RobotsTxt     bool     `json:"robots_txt,omitempty"`
	ContentLength int64    `json:"content_length,omitempty"`
}

// Software is a software/package inventory item on an asset (agent-collected).
type Software struct {
	ID      string `json:"id"`
	AssetID string `json:"asset_id"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	// VersionNorm is the ingestion-normalized form of Version: scanner
	// noise stripped, validated and canonicalized under the ecosystem's
	// package grammar (fingerprinting.NormalizeObservedVersion). Empty
	// until the row's next report refresh; matching falls back to the
	// raw Version meanwhile. Version itself is never rewritten.
	VersionNorm string    `json:"version_norm,omitempty"`
	Vendor      string    `json:"vendor,omitempty"`
	Ecosystem   string    `json:"ecosystem,omitempty"` // os_debian, os_rpm, os_alpine, npm, pypi, go, maven, nuget, winget...
	PURL        string    `json:"purl,omitempty"`      // package URL, normalized
	CPEs        []string  `json:"cpes,omitempty"`
	Source      string    `json:"source,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// PURL builds a normalized package URL from components (best-effort, no guessing).
func PURL(ecosystem, name, version string) string {
	if ecosystem == "" || name == "" {
		return ""
	}
	p := "pkg:" + ecosystem + "/" + name
	if version != "" {
		p += "@" + version
	}
	return p
}
