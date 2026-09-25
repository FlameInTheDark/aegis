// Package alerting implements the business alert-trigger engine: a
// transactional event outbox, event and device-metric trigger evaluation
// with persistent occurrence state, and durable signed delivery. It is
// deliberately independent of the sensor detection engine (internal/
// detections): detection rules correlate security events in a time window;
// alert triggers evaluate reliable domain transitions and metric
// thresholds with cooldown, recovery and audit.
package alerting

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// SchemaVersion of the TriggerEvent envelope.
const SchemaVersion = 1

// Initial event catalog (plan §5.2): only transitions that have a reliable,
// tested producer are declared. Anything not listed here cannot be selected
// by a trigger — the capabilities API is the single source of truth.
const (
	EventAssetDiscovered           = "asset.discovered"
	EventAssetDeleted              = "asset.deleted"
	EventDeviceBound               = "device.bound"
	EventServiceDiscovered         = "service.discovered"
	EventServiceChanged            = "service.changed"
	EventSoftwareInstalled         = "software.installed"
	EventFindingCreated            = "finding.created"
	EventFindingStatusChanged      = "finding.status_changed"
	EventScanStateChanged          = "scan.state_changed"
	EventAgentStateChanged         = "agent.state_changed"
	EventFeedSyncCompleted         = "feed.sync.completed"
	EventFeedSyncPartial           = "feed.sync.partial"
	EventFeedSyncFailed            = "feed.sync.failed"
	EventFeedStale                 = "feed.stale"
	EventFeedRecovered             = "feed.recovered"
	EventDetectionMatchCreated     = "detection.match.created"
	EventVulnerabilityIndexUpdated = "vulnerability.index.updated"
)

// NewEvent builds an envelope with defaults filled (ids, timestamps,
// schema version). Data is JSON-encoded when it is not raw JSON already.
func NewEvent(orgID, typ, source string, data any) *domain.TriggerEvent {
	ev := &domain.TriggerEvent{
		EventID:        ids.New(),
		SchemaVersion:  SchemaVersion,
		Type:           typ,
		Source:         source,
		OrganizationID: orgID,
		OccurredAt:     time.Now().UTC(),
	}
	switch d := data.(type) {
	case nil:
	case json.RawMessage:
		ev.Data = d
	case []byte:
		ev.Data = json.RawMessage(d)
	default:
		if b, err := json.Marshal(d); err == nil {
			ev.Data = json.RawMessage(b)
		}
	}
	return ev
}

// Emit persists one event to the outbox. Call it on the same write path as
// the mutation that caused the event; the dedup_key keeps replays harmless
// for the evaluator.
func Emit(ctx context.Context, db *pg.DB, ev *domain.TriggerEvent) error {
	if ev == nil || ev.OrganizationID == "" {
		return fmt.Errorf("alerting: emit: event and organization are required")
	}
	return pg.NewOutboxRepo(db).Insert(ctx, ev)
}

// EventData is the common shape emitters use for the data payload. Fields
// are flattened into the condition-evaluation map by the engine, so a
// condition can address e.g. "device_type" or "state".
type EventData map[string]any

// --- Typed emit helpers for the reliable catalog ---------------------------

// EmitAssetDiscovered fires when a NEW asset is provisioned (scan or agent
// path). dedup key is the asset id: re-provisioning the same device can
// never storm triggers.
func EmitAssetDiscovered(ctx context.Context, db *pg.DB, orgID, siteID, assetID, hostname, source, deviceType string) error {
	ev := NewEvent(orgID, EventAssetDiscovered, source, EventData{
		"hostname": hostname, "device_type": deviceType,
	})
	ev.SiteID, ev.AssetID = siteID, assetID
	ev.EntityType, ev.EntityID = "asset", assetID
	ev.Severity = string(domain.SeverityInfo)
	ev.DedupKey = "asset:" + assetID
	return Emit(ctx, db, ev)
}

// EmitAssetDeleted fires when an operator deletes an asset.
func EmitAssetDeleted(ctx context.Context, db *pg.DB, orgID, siteID, assetID, source string) error {
	ev := NewEvent(orgID, EventAssetDeleted, source, nil)
	ev.SiteID, ev.AssetID = siteID, assetID
	ev.EntityType, ev.EntityID = "asset", assetID
	ev.Severity = string(domain.SeverityLow)
	ev.DedupKey = "asset-deleted:" + assetID
	return Emit(ctx, db, ev)
}

// EmitDeviceBound fires when an endpoint device is bound to a connector.
func EmitDeviceBound(ctx context.Context, db *pg.DB, orgID, siteID, assetID, agentID string) error {
	ev := NewEvent(orgID, EventDeviceBound, "agent", EventData{"agent_id": agentID})
	ev.SiteID, ev.AssetID = siteID, assetID
	ev.EntityType, ev.EntityID = "asset", assetID
	ev.Severity = string(domain.SeverityInfo)
	ev.DedupKey = "device-bound:" + assetID + ":" + agentID
	return Emit(ctx, db, ev)
}

// EmitService emits service.discovered / service.changed.
func EmitService(ctx context.Context, db *pg.DB, orgID, siteID, assetID, svcID, port, productName string, changed bool) error {
	typ := EventServiceDiscovered
	if changed {
		typ = EventServiceChanged
	}
	ev := NewEvent(orgID, typ, "scanner", EventData{
		"port": port, "product": productName,
	})
	ev.SiteID, ev.AssetID = siteID, assetID
	ev.EntityType, ev.EntityID = "service", svcID
	ev.Severity = string(domain.SeverityInfo)
	ev.DedupKey = "service:" + svcID + ":" + typ
	return Emit(ctx, db, ev)
}

// EmitSoftwareInstalled fires when a package row is first recorded.
func EmitSoftwareInstalled(ctx context.Context, db *pg.DB, orgID, siteID, assetID, swID, name, version, ecosystem string) error {
	ev := NewEvent(orgID, EventSoftwareInstalled, "agent", EventData{
		"name": name, "version": version, "ecosystem": ecosystem,
	})
	ev.SiteID, ev.AssetID = siteID, assetID
	ev.EntityType, ev.EntityID = "software", swID
	ev.Severity = string(domain.SeverityInfo)
	ev.DedupKey = "software:" + swID
	return Emit(ctx, db, ev)
}

// EmitFindingCreated fires only for genuinely NEW findings (the upsert
// reports created=false on refresh, which emits nothing — a rescan must
// never storm finding triggers).
func EmitFindingCreated(ctx context.Context, db *pg.DB, orgID, siteID, assetID, findingID, cveID, severity string, kev bool, epss float64) error {
	ev := NewEvent(orgID, EventFindingCreated, "finding", EventData{
		"cve_id": cveID, "kev": kev, "epss": epss,
	})
	ev.SiteID, ev.AssetID = siteID, assetID
	ev.EntityType, ev.EntityID = "finding", findingID
	ev.Severity = severity
	ev.DedupKey = "finding:" + findingID
	return Emit(ctx, db, ev)
}

// EmitFindingStatusChanged fires for real status transitions performed via
// the API (resolved, reopened, suppressed...).
func EmitFindingStatusChanged(ctx context.Context, db *pg.DB, orgID, siteID, assetID, findingID, from, to, actor string) error {
	ev := NewEvent(orgID, EventFindingStatusChanged, "finding", EventData{
		"from": from, "to": to, "actor": actor,
	})
	ev.SiteID, ev.AssetID = siteID, assetID
	ev.EntityType, ev.EntityID = "finding", findingID
	ev.Severity = string(domain.SeverityLow)
	ev.DedupKey = "finding-status:" + findingID + ":" + to + ":" + ev.OccurredAt.Format(time.RFC3339Nano)
	return Emit(ctx, db, ev)
}

// EmitScanStateChanged fires from the scan-result consumer for terminal
// scan transitions.
func EmitScanStateChanged(ctx context.Context, db *pg.DB, orgID, siteID, scanID, state, scanType string, findings int) error {
	ev := NewEvent(orgID, EventScanStateChanged, "scanner", EventData{
		"scan_id": scanID, "state": state, "scan_type": scanType, "findings_created": findings,
	})
	ev.SiteID = siteID
	ev.EntityType, ev.EntityID = "scan", scanID
	if state == "failed" {
		ev.Severity = string(domain.SeverityHigh)
	} else {
		ev.Severity = string(domain.SeverityInfo)
	}
	ev.DedupKey = "scan:" + scanID + ":" + state
	return Emit(ctx, db, ev)
}

// EmitAgentStateChanged fires for offline transitions computed by the
// worker's liveness sweep (marking online is handled by device.bound and
// regular telemetry, which would otherwise fire on every heartbeat).
func EmitAgentStateChanged(ctx context.Context, db *pg.DB, orgID, siteID, agentID, assetID, state string) error {
	ev := NewEvent(orgID, EventAgentStateChanged, "agent", EventData{"state": state})
	ev.SiteID, ev.AssetID = siteID, assetID
	ev.EntityType, ev.EntityID = "agent", agentID
	ev.Severity = string(domain.SeverityMedium)
	ev.DedupKey = "agent:" + agentID + ":" + state + ":" + ev.OccurredAt.Format(time.RFC3339)
	return Emit(ctx, db, ev)
}

// EmitFeedSync fires feed.sync.completed / partial / failed after a feed
// run finishes, and vulnerability.index.updated on full success.
func EmitFeedSync(ctx context.Context, db *pg.DB, orgID, feedName, status string, records int64, errText string) error {
	typ := EventFeedSyncCompleted
	switch status {
	case "partial":
		typ = EventFeedSyncPartial
	case "failed":
		typ = EventFeedSyncFailed
	}
	data := EventData{"feed": feedName, "records": records}
	if errText != "" {
		data["error"] = errText
	}
	ev := NewEvent(orgID, typ, "feed", data)
	ev.EntityType, ev.EntityID = "feed", feedName
	switch typ {
	case EventFeedSyncFailed:
		ev.Severity = string(domain.SeverityHigh)
	case EventFeedSyncPartial:
		ev.Severity = string(domain.SeverityMedium)
	default:
		ev.Severity = string(domain.SeverityInfo)
	}
	ev.DedupKey = "feed:" + feedName + ":" + status + ":" + ev.OccurredAt.Format(time.RFC3339)
	if err := Emit(ctx, db, ev); err != nil {
		return err
	}
	if typ == EventFeedSyncCompleted {
		idx := NewEvent(orgID, EventVulnerabilityIndexUpdated, "feed", EventData{"feed": feedName, "records": records})
		idx.EntityType, idx.EntityID = "feed", feedName
		idx.Severity = string(domain.SeverityInfo)
		idx.DedupKey = "vuln-index:" + feedName + ":" + idx.OccurredAt.Format(time.RFC3339)
		return Emit(ctx, db, idx)
	}
	return nil
}

// EmitFeedStaleness fires feed.stale / feed.recovered; the stable dedup key
// per feed lets a trigger recover a stale occurrence when the feed catches
// up (feed.recovered uses the same fingerprint base).
func EmitFeedStaleness(ctx context.Context, db *pg.DB, orgID, feedName string, stale bool) error {
	typ := EventFeedRecovered
	severity := string(domain.SeverityInfo)
	if stale {
		typ = EventFeedStale
		severity = string(domain.SeverityMedium)
	}
	ev := NewEvent(orgID, typ, "feed", EventData{"feed": feedName})
	ev.EntityType, ev.EntityID = "feed", feedName
	ev.Severity = severity
	// STABLE fingerprint across staleness episodes: the evaluator resolves
	// the open occurrence when the recovery event arrives.
	ev.DedupKey = "feed-health:" + feedName
	return Emit(ctx, db, ev)
}

// EmitDetectionMatchCreated fires when the sensor correlation engine
// records a match.
func EmitDetectionMatchCreated(ctx context.Context, db *pg.DB, orgID, siteID, assetID, matchID, ruleTitle, level string) error {
	ev := NewEvent(orgID, EventDetectionMatchCreated, "sensor", EventData{
		"rule_title": ruleTitle, "level": level,
	})
	ev.SiteID, ev.AssetID = siteID, assetID
	ev.EntityType, ev.EntityID = "detection_match", matchID
	ev.Severity = level
	ev.DedupKey = "detection:" + matchID
	return Emit(ctx, db, ev)
}
