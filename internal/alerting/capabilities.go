package alerting

import "github.com/FlameInTheDark/aegis/internal/domain"

// Capabilities is the server-advertised trigger catalog. The UI builds the
// editor exclusively from this response — it never hard-codes event types,
// metric fields or operators the server did not advertise (plan §5.11).
type Capabilities struct {
	EventTypes       []EventTypeInfo   `json:"event_types"`
	MetricFields     []MetricFieldInfo `json:"metric_fields"`
	Aggregations     []string          `json:"aggregations"`
	Operators        []OperatorInfo    `json:"operators"`
	Severities       []string          `json:"severities"`
	Lifecycles       []string          `json:"lifecycles"`
	MissingData      []string          `json:"missing_data_policies"`
	GroupBy          []string          `json:"group_by"`
	WindowPresets    []WindowPreset    `json:"window_presets"`
	DurationSteps    []int             `json:"duration_steps"`
	DeliveryKinds    []string          `json:"delivery_kinds"`
	DestinationKinds []string          `json:"destination_kinds"`
}

// EventTypeInfo describes one triggerable event type.
type EventTypeInfo struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	// Fields the condition builder can address for this event type.
	Fields []FieldInfo `json:"fields"`
}

// FieldInfo is one condition-addressable field.
type FieldInfo struct {
	Field string `json:"field"`
	Type  string `json:"type"` // string | number | boolean
}

// MetricFieldInfo describes one metric trigger source.
type MetricFieldInfo struct {
	Field       string `json:"field"`
	Unit        string `json:"unit"`
	Description string `json:"description"`
}

// OperatorInfo carries the human label for an operator.
type OperatorInfo struct {
	Op    string `json:"op"`
	Label string `json:"label"`
	Kind  string `json:"kind"` // number | string | list | exists | regex
}

// WindowPreset is a quick-pick evaluation window.
type WindowPreset struct {
	Secs  int    `json:"secs"`
	Label string `json:"label"`
}

// Catalog returns the advertised capability catalog.
func Catalog() Capabilities {
	return Capabilities{
		EventTypes: eventCatalog(),
		MetricFields: []MetricFieldInfo{
			{Field: "cpu_percent", Unit: "%", Description: "CPU utilization"},
			{Field: "mem_used_percent", Unit: "%", Description: "Memory used as a share of installed memory"},
			{Field: "rx_bps", Unit: "bytes/s", Description: "Receive throughput"},
			{Field: "tx_bps", Unit: "bytes/s", Description: "Transmit throughput"},
			{Field: "load1", Unit: "", Description: "1-minute load average"},
			{Field: "load5", Unit: "", Description: "5-minute load average"},
			{Field: "load15", Unit: "", Description: "15-minute load average"},
		},
		Aggregations: Aggregations,
		Operators: []OperatorInfo{
			{Op: OpEq, Label: "is", Kind: "any"},
			{Op: OpNeq, Label: "is not", Kind: "any"},
			{Op: OpIn, Label: "is one of", Kind: "list"},
			{Op: OpNotIn, Label: "is none of", Kind: "list"},
			{Op: OpGt, Label: "above", Kind: "number"},
			{Op: OpGte, Label: "at or above", Kind: "number"},
			{Op: OpLt, Label: "below", Kind: "number"},
			{Op: OpLte, Label: "at or below", Kind: "number"},
			{Op: OpContains, Label: "contains", Kind: "string"},
			{Op: OpStartsWith, Label: "starts with", Kind: "string"},
			{Op: OpEndsWith, Label: "ends with", Kind: "string"},
			{Op: OpExists, Label: "exists", Kind: "exists"},
			{Op: OpRegex, Label: "matches", Kind: "regex"},
		},
		Severities: []string{
			string(domain.SeverityInfo), string(domain.SeverityLow),
			string(domain.SeverityMedium), string(domain.SeverityHigh), string(domain.SeverityCritical),
		},
		Lifecycles:  []string{domain.TriggerLifecycleStable, domain.TriggerLifecycleExperimental, domain.TriggerLifecycleDeprecated},
		MissingData: []string{domain.MissingDataIgnore, domain.MissingDataTrigger, domain.MissingDataResolve},
		GroupBy:     []string{"asset"},
		WindowPresets: []WindowPreset{
			{Secs: 60, Label: "1 minute"},
			{Secs: 300, Label: "5 minutes"},
			{Secs: 900, Label: "15 minutes"},
			{Secs: 1800, Label: "30 minutes"},
			{Secs: 3600, Label: "1 hour"},
		},
		DurationSteps:    []int{0, 60, 120, 300, 600, 900, 1800, 3600},
		DeliveryKinds:    []string{domain.DeliveryFired, domain.DeliveryRecovered, domain.DeliveryRepeat, domain.DeliveryTest},
		DestinationKinds: []string{domain.DestinationWebhook, domain.DestinationInApp},
	}
}

func eventCatalog() []EventTypeInfo {
	return []EventTypeInfo{
		{Type: EventAssetDiscovered, Description: "A new device joined the inventory (scan or endpoint enrollment)", Fields: []FieldInfo{
			{Field: "hostname", Type: "string"}, {Field: "device_type", Type: "string"}, {Field: "source", Type: "string"},
		}},
		{Type: EventAssetDeleted, Description: "A device was removed from the inventory", Fields: []FieldInfo{
			{Field: "source", Type: "string"},
		}},
		{Type: EventDeviceBound, Description: "An endpoint device was bound to a connector", Fields: []FieldInfo{
			{Field: "agent_id", Type: "string"},
		}},
		{Type: EventServiceDiscovered, Description: "A network service was observed for the first time", Fields: []FieldInfo{
			{Field: "port", Type: "string"}, {Field: "product", Type: "string"},
		}},
		{Type: EventServiceChanged, Description: "A known service changed its product or banner", Fields: []FieldInfo{
			{Field: "port", Type: "string"}, {Field: "product", Type: "string"},
		}},
		{Type: EventSoftwareInstalled, Description: "A software package was recorded for the first time", Fields: []FieldInfo{
			{Field: "name", Type: "string"}, {Field: "version", Type: "string"}, {Field: "ecosystem", Type: "string"},
		}},
		{Type: EventFindingCreated, Description: "A new vulnerability finding was created by correlation", Fields: []FieldInfo{
			{Field: "cve_id", Type: "string"}, {Field: "kev", Type: "boolean"}, {Field: "epss", Type: "number"},
		}},
		{Type: EventFindingStatusChanged, Description: "A finding changed status (resolved, reopened, suppressed)", Fields: []FieldInfo{
			{Field: "from", Type: "string"}, {Field: "to", Type: "string"}, {Field: "actor", Type: "string"},
		}},
		{Type: EventScanStateChanged, Description: "A scan completed or failed", Fields: []FieldInfo{
			{Field: "state", Type: "string"}, {Field: "scan_type", Type: "string"}, {Field: "findings_created", Type: "number"},
		}},
		{Type: EventAgentStateChanged, Description: "An endpoint agent went offline", Fields: []FieldInfo{
			{Field: "state", Type: "string"},
		}},
		{Type: EventFeedSyncCompleted, Description: "A vulnerability feed sync finished successfully", Fields: []FieldInfo{
			{Field: "feed", Type: "string"}, {Field: "records", Type: "number"},
		}},
		{Type: EventFeedSyncPartial, Description: "A vulnerability feed sync finished with partial results", Fields: []FieldInfo{
			{Field: "feed", Type: "string"}, {Field: "records", Type: "number"},
		}},
		{Type: EventFeedSyncFailed, Description: "A vulnerability feed sync failed", Fields: []FieldInfo{
			{Field: "feed", Type: "string"}, {Field: "error", Type: "string"},
		}},
		{Type: EventFeedStale, Description: "A vulnerability feed has not synced within its expected interval", Fields: []FieldInfo{
			{Field: "feed", Type: "string"},
		}},
		{Type: EventFeedRecovered, Description: "A previously stale feed synced again", Fields: []FieldInfo{
			{Field: "feed", Type: "string"},
		}},
		{Type: EventDetectionMatchCreated, Description: "The sensor detection engine produced a match", Fields: []FieldInfo{
			{Field: "rule_title", Type: "string"}, {Field: "level", Type: "string"},
		}},
		{Type: EventVulnerabilityIndexUpdated, Description: "The local vulnerability index was refreshed by a feed", Fields: []FieldInfo{
			{Field: "feed", Type: "string"}, {Field: "records", Type: "number"},
		}},
	}
}
