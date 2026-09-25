package domain

import (
	"encoding/json"
	"time"
)

// Alert trigger kinds.
const (
	TriggerKindEvent  = "event"
	TriggerKindMetric = "device_metric"
)

// Alert trigger lifecycle stages. Lifecycle is orthogonal to enabled: a
// disabled trigger is paused; a deprecated one still runs but is not
// recommended for new authoring.
const (
	TriggerLifecycleStable       = "stable"
	TriggerLifecycleExperimental = "experimental"
	TriggerLifecycleDeprecated   = "deprecated"
)

// Alert occurrence states. normal/pending are rule-state (evaluation)
// states; occurrences only exist for episodes that fired.
const (
	OccurrenceFiring       = "firing"
	OccurrenceAcknowledged = "acknowledged"
	OccurrenceRecovered    = "recovered"
	OccurrenceSuppressed   = "suppressed"
)

// Rule evaluation states (alert_rule_states.state).
const (
	RuleStateNormal   = "normal"
	RuleStatePending  = "pending"
	RuleStateFiring   = "firing"
	RuleStateDegraded = "degraded"
)

// Delivery statuses.
const (
	DeliveryPending = "pending"
	DeliveryRetry   = "retry"
	DeliverySent    = "sent"
	DeliveryDead    = "dead"
)

// Delivery kinds.
const (
	DeliveryFired     = "fired"
	DeliveryRecovered = "recovered"
	DeliveryRepeat    = "repeat"
	DeliveryTest      = "test"
)

// Destination kinds.
const (
	DestinationWebhook = "webhook"
	DestinationInApp   = "in_app"
)

// Missing-data policies for metric triggers.
const (
	MissingDataIgnore  = "ignore"
	MissingDataTrigger = "trigger"
	MissingDataResolve = "resolve"
)

// TriggerScope restricts which entities a trigger evaluates.
type TriggerScope struct {
	SiteIDs     []string `json:"site_ids,omitempty"`
	AssetIDs    []string `json:"asset_ids,omitempty"`
	DeviceTypes []string `json:"device_types,omitempty"`
}

// Trigger is one organization-scoped alert rule.
type Trigger struct {
	ID          string          `json:"id"`
	OrgID       string          `json:"organization_id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Kind        string          `json:"kind"`
	Enabled     bool            `json:"enabled"`
	Lifecycle   string          `json:"lifecycle"`
	Severity    string          `json:"severity"`
	Scope       TriggerScope    `json:"scope"`
	Conditions  json.RawMessage `json:"conditions"`
	// Event triggers: the event types listened to, and the types that
	// resolve (recover) matching open occurrences.
	EventTypes         []string `json:"event_types"`
	RecoveryEventTypes []string `json:"recovery_event_types"`
	// Metric triggers.
	MetricField       string   `json:"metric_field"`
	Aggregation       string   `json:"aggregation"`
	Operator          string   `json:"operator"`
	Threshold         float64  `json:"threshold"`
	WindowSecs        int      `json:"window_secs"`
	GroupBy           string   `json:"group_by"`
	ActivationSecs    int      `json:"activation_secs"`
	RecoverySecs      int      `json:"recovery_secs"`
	RecoveryThreshold *float64 `json:"recovery_threshold,omitempty"`
	MissingDataPolicy string   `json:"missing_data_policy"`
	// Behavior.
	CooldownSecs   int      `json:"cooldown_secs"`
	RepeatSecs     int      `json:"repeat_secs"`
	DestinationIDs []string `json:"destination_ids"`
	// Ownership and runtime metadata.
	Revision        int        `json:"revision"`
	CreatedBy       string     `json:"created_by"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	LastEvaluatedAt *time.Time `json:"last_evaluated_at,omitempty"`
	LastError       string     `json:"last_error"`
}

// Destination is a delivery channel for alert notifications.
type Destination struct {
	ID            string     `json:"id"`
	OrgID         string     `json:"organization_id"`
	Kind          string     `json:"kind"`
	Name          string     `json:"name"`
	URL           string     `json:"url"`
	Secret        string     `json:"-"` // never serialized; returned only masked
	Events        []string   `json:"events"`
	MinSeverity   string     `json:"min_severity"`
	Enabled       bool       `json:"enabled"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	LastError     string     `json:"last_error"`
	// SecretMasked is set by the repo layer for API responses.
	SecretMasked string `json:"secret_masked,omitempty"`
}

// Occurrence is one alert episode.
type Occurrence struct {
	ID              string          `json:"id"`
	OrgID           string          `json:"organization_id"`
	TriggerID       string          `json:"trigger_id"`
	Fingerprint     string          `json:"fingerprint"`
	State           string          `json:"state"`
	Severity        string          `json:"severity"`
	Title           string          `json:"title"`
	Summary         string          `json:"summary"`
	SiteID          string          `json:"site_id,omitempty"`
	AssetID         string          `json:"asset_id,omitempty"`
	EntityType      string          `json:"entity_type,omitempty"`
	EntityID        string          `json:"entity_id,omitempty"`
	Snapshot        json.RawMessage `json:"snapshot"`
	Evidence        json.RawMessage `json:"evidence"`
	OccurrenceCount int             `json:"occurrence_count"`
	OpenedAt        time.Time       `json:"opened_at"`
	AcknowledgedAt  *time.Time      `json:"acknowledged_at,omitempty"`
	RecoveredAt     *time.Time      `json:"recovered_at,omitempty"`
	UpdatedAt       time.Time       `json:"updated_at"`
	// Joined for display (repo fills when available).
	TriggerName string `json:"trigger_name,omitempty"`
}

// Transition is one immutable lifecycle change of an occurrence.
type Transition struct {
	ID            string    `json:"id"`
	OrgID         string    `json:"organization_id"`
	OccurrenceID  string    `json:"occurrence_id"`
	FromState     string    `json:"from_state"`
	ToState       string    `json:"to_state"`
	EventID       string    `json:"event_id"`
	ObservedValue *float64  `json:"observed_value,omitempty"`
	Actor         string    `json:"actor"`
	Reason        string    `json:"reason"`
	RequestID     string    `json:"request_id"`
	CreatedAt     time.Time `json:"created_at"`
}

// Delivery is one notification attempt against one destination.
type Delivery struct {
	ID              string          `json:"id"`
	OrgID           string          `json:"organization_id"`
	OccurrenceID    string          `json:"occurrence_id"`
	DestinationID   string          `json:"destination_id"`
	TransitionID    string          `json:"transition_id,omitempty"`
	Kind            string          `json:"kind"`
	Status          string          `json:"status"`
	Attempts        int             `json:"attempts"`
	NextAttemptAt   time.Time       `json:"next_attempt_at"`
	LastStatusCode  *int            `json:"last_status_code,omitempty"`
	LastError       string          `json:"last_error"`
	IdempotencyKey  string          `json:"idempotency_key"`
	Payload         json.RawMessage `json:"payload"`
	CreatedAt       time.Time       `json:"created_at"`
	SentAt          *time.Time      `json:"sent_at,omitempty"`
	DestinationName string          `json:"destination_name,omitempty"`
}

// TriggerEvent is the versioned business-event envelope that flows through
// the outbox into the alert evaluator. It is independent of the sensor
// detection-event model.
type TriggerEvent struct {
	EventID        string          `json:"event_id"`
	SchemaVersion  int             `json:"schema_version"`
	Type           string          `json:"type"`
	Source         string          `json:"source"`
	OrganizationID string          `json:"organization_id"`
	SiteID         string          `json:"site_id,omitempty"`
	AssetID        string          `json:"asset_id,omitempty"`
	EntityType     string          `json:"entity_type,omitempty"`
	EntityID       string          `json:"entity_id,omitempty"`
	OccurredAt     time.Time       `json:"occurred_at"`
	RecordedAt     time.Time       `json:"recorded_at"`
	CorrelationID  string          `json:"correlation_id,omitempty"`
	CausationID    string          `json:"causation_id,omitempty"`
	Severity       string          `json:"severity,omitempty"`
	Data           json.RawMessage `json:"data,omitempty"`
	DedupKey       string          `json:"dedup_key,omitempty"`
}

// OutboxEvent is one persisted outbox row.
type OutboxEvent struct {
	ID            string          `json:"id"`
	OrgID         string          `json:"organization_id"`
	Type          string          `json:"type"`
	SchemaVersion int             `json:"schema_version"`
	SubjectType   string          `json:"subject_type"`
	SubjectID     string          `json:"subject_id"`
	SiteID        string          `json:"site_id,omitempty"`
	AssetID       string          `json:"asset_id,omitempty"`
	EntityType    string          `json:"entity_type,omitempty"`
	EntityID      string          `json:"entity_id,omitempty"`
	OccurredAt    time.Time       `json:"occurred_at"`
	RecordedAt    time.Time       `json:"recorded_at"`
	Payload       json.RawMessage `json:"payload"`
	CorrelationID string          `json:"correlation_id,omitempty"`
	CausationID   string          `json:"causation_id,omitempty"`
	DedupKey      string          `json:"dedup_key,omitempty"`
	PublishedAt   *time.Time      `json:"published_at,omitempty"`
	Attempts      int             `json:"attempts"`
	NextAttemptAt time.Time       `json:"next_attempt_at"`
	LastError     string          `json:"last_error,omitempty"`
}

// CorrelationJob is one unit of durable background work.
type CorrelationJob struct {
	ID             string          `json:"id"`
	OrgID          string          `json:"organization_id"`
	Kind           string          `json:"kind"`
	Payload        json.RawMessage `json:"payload"`
	State          string          `json:"state"`
	Attempts       int             `json:"attempts"`
	LeaseUntil     *time.Time      `json:"lease_until,omitempty"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	LastError      string          `json:"last_error,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	StartedAt      *time.Time      `json:"started_at,omitempty"`
	FinishedAt     *time.Time      `json:"finished_at,omitempty"`
}

// Correlation job kinds.
const (
	JobCorrelateOrg    = "correlate_org"
	JobCorrelateAsset  = "correlate_asset"
	JobSearchActionRun = "search_action_run"
)

// VulnSearchAction is a declarative, local-only vulnerability search plan.
type VulnSearchAction struct {
	ID            string          `json:"id"`
	OrgID         string          `json:"organization_id"`
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	TargetKind    string          `json:"target_kind"`
	Selector      json.RawMessage `json:"selector"`
	Mode          string          `json:"mode"`
	Priority      int             `json:"priority"`
	Enabled       bool            `json:"enabled"`
	VersionPolicy json.RawMessage `json:"version_policy"`
	ConfidenceCap float64         `json:"confidence_cap"`
	Revision      int             `json:"revision"`
	CreatedBy     string          `json:"created_by"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// VulnSearchRun is one execution of an action revision.
type VulnSearchRun struct {
	ID              string          `json:"id"`
	OrgID           string          `json:"organization_id"`
	ActionID        string          `json:"action_id"`
	Revision        int             `json:"revision"`
	State           string          `json:"state"`
	Progress        int             `json:"progress"`
	Requester       string          `json:"requester"`
	IdempotencyKey  string          `json:"idempotency_key,omitempty"`
	Candidates      int             `json:"candidates"`
	Matches         int             `json:"matches"`
	FindingsCreated int             `json:"findings_created"`
	Errors          json.RawMessage `json:"errors"`
	StartedAt       *time.Time      `json:"started_at,omitempty"`
	FinishedAt      *time.Time      `json:"finished_at,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
}

// VulnMatchProvenance explains why one match exists.
type VulnMatchProvenance struct {
	ID               string          `json:"id"`
	OrgID            string          `json:"organization_id"`
	FindingID        string          `json:"finding_id"`
	ActionID         string          `json:"action_id,omitempty"`
	Revision         int             `json:"revision,omitempty"`
	RunID            string          `json:"run_id,omitempty"`
	TargetType       string          `json:"target_type"`
	TargetID         string          `json:"target_id"`
	Origin           string          `json:"origin"`
	Source           string          `json:"source"`
	CPEKey           string          `json:"cpe_key,omitempty"`
	MatchType        string          `json:"match_type,omitempty"`
	Confidence       float64         `json:"confidence"`
	ObservedIdentity json.RawMessage `json:"observed_identity"`
	Reason           string          `json:"reason,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
}

// VulnIdentityAlias maps an observed product name to a canonical identity.
type VulnIdentityAlias struct {
	ID                 string    `json:"id"`
	OrgID              string    `json:"organization_id"`
	Name               string    `json:"name"`
	Vendor             string    `json:"vendor"`
	Product            string    `json:"product"`
	Ecosystem          string    `json:"ecosystem"`
	CanonicalPart      string    `json:"canonical_part"`
	CanonicalVendor    string    `json:"canonical_vendor"`
	CanonicalProduct   string    `json:"canonical_product"`
	CanonicalEcosystem string    `json:"canonical_ecosystem"`
	Confidence         float64   `json:"confidence"`
	Reason             string    `json:"reason"`
	CreatedBy          string    `json:"created_by"`
	CreatedAt          time.Time `json:"created_at"`
}

// Local vulnerability source allowlist.
const (
	VulnSourceCPE         = "cpe"
	VulnSourceCVEAffected = "cve_affected"
	VulnSourceOSV         = "osv"
	VulnSourceOVAL        = "oval"
)

// Search action modes.
const (
	VulnActionModeShadow       = "shadow"
	VulnActionModeAugment      = "augment"
	VulnActionModeFallbackOnly = "fallback_only"
)

// VulnSearchStatus is the availability of each local source.
type VulnSearchStatus struct {
	CPE         bool   `json:"cpe"`
	OSV         bool   `json:"osv"`
	OVAL        bool   `json:"oval"`
	CVEAffected bool   `json:"cve_affected"`
	Records     int64  `json:"records"`
	Detail      string `json:"detail,omitempty"`
}
