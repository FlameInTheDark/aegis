package domain

import (
	"time"
)

// NodeKind is a topology node type.
type NodeKind string

const (
	NodeAsset   NodeKind = "asset"
	NodeIface   NodeKind = "interface"
	NodeNetwork NodeKind = "network"
	NodeVLAN    NodeKind = "vlan"
	NodeRouter  NodeKind = "router"
	NodeSwitch  NodeKind = "switch"
	NodeAP      NodeKind = "access_point"
	NodeGateway NodeKind = "gateway"
	NodeScanner NodeKind = "scanner"
	NodeSensor  NodeKind = "sensor"
)

// EdgeKind is a topology relationship type.
type EdgeKind string

const (
	EdgeConnectedTo  EdgeKind = "connected_to"
	EdgeRoutesTo     EdgeKind = "routes_to"
	EdgeAttachedTo   EdgeKind = "attached_to"
	EdgeNeighborOf   EdgeKind = "neighbor_of"
	EdgeObservedThru EdgeKind = "observed_through"
	EdgeCommunicates EdgeKind = "communicates_with"
)

// TopologyNode is a vertex in the site topology graph.
type TopologyNode struct {
	ID             string         `json:"id"`
	OrganizationID string         `json:"organization_id"`
	SiteID         string         `json:"site_id"`
	Kind           NodeKind       `json:"kind"`
	RefID          string         `json:"ref_id"` // asset/network/vlan id
	Label          string         `json:"label,omitempty"`
	Props          map[string]any `json:"props,omitempty"`
	FirstSeen      time.Time      `json:"first_seen"`
	LastSeen       time.Time      `json:"last_seen"`
}

// TopologyEdge is an evidence-backed relationship. Inferred topology is
// never presented as guaranteed truth: confidence + evidence always ship.
type TopologyEdge struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	SiteID         string     `json:"site_id"`
	SrcNodeID      string     `json:"src_node_id"`
	DstNodeID      string     `json:"dst_node_id"`
	Kind           EdgeKind   `json:"kind"`
	Confidence     Confidence `json:"confidence"`
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
}

// TopologyEvidence is one observation supporting an edge.
type TopologyEvidence struct {
	ID         string         `json:"id"`
	EdgeID     string         `json:"edge_id"`
	Source     Source         `json:"source"` // snmp|lldp|cdp|arp|ndp|mac_table|routing|agent|flow|scanner
	Statement  string         `json:"statement"`
	Detail     map[string]any `json:"detail,omitempty"`
	ObservedAt time.Time      `json:"observed_at"`
}

// TopologyGraph is the response shape for the UI graph view.
type TopologyGraph struct {
	SiteID string         `json:"site_id"`
	Nodes  []TopologyNode `json:"nodes"`
	Edges  []TopologyEdge `json:"edges"`
	Evict  int            `json:"node_count"`
}
