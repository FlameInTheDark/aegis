-- 0035 (v1.30.0): alert-trigger engine and vulnerability search actions.
--
-- Two planes share this migration:
--   * Alerting: a transactional event outbox feeds the trigger evaluator;
--     rule state, occurrences, transitions and deliveries are authoritative
--     in PostgreSQL (never Redis/NATS). Deliveries carry an idempotency key
--     so replays are harmless; open occurrences are protected by a partial
--     unique index (one open episode per trigger/fingerprint).
--   * Vulnerability search actions: declarative, local-only search plans
--     over the synchronized NVD/CVE/OSV/OVAL indexes, with immutable
--     revisions, durable runs and per-match provenance. Nothing here can
--     encode a URL, command or query — sources are an allowlist of the
--     four local index types.
--
-- The migration is additive: no existing table or column is modified, so
-- rollback is a plain drop and the previous release keeps working.

-- ---------------------------------------------------------------------------
-- Event outbox: domain events committed next to the mutation that caused
-- them; a relay publishes them to the dedicated alert stream and marks the
-- row only after the broker acknowledges.
CREATE TABLE IF NOT EXISTS event_outbox (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    type            TEXT NOT NULL,
    schema_version  INT NOT NULL DEFAULT 1,
    subject_type    TEXT NOT NULL DEFAULT '',
    subject_id      TEXT NOT NULL DEFAULT '',
    site_id         UUID,
    asset_id        UUID,
    entity_type     TEXT NOT NULL DEFAULT '',
    entity_id       TEXT NOT NULL DEFAULT '',
    occurred_at     TIMESTAMPTZ NOT NULL,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    payload         JSONB NOT NULL,
    correlation_id  TEXT NOT NULL DEFAULT '',
    causation_id    TEXT NOT NULL DEFAULT '',
    dedup_key       TEXT NOT NULL DEFAULT '',
    published_at    TIMESTAMPTZ,
    attempts        INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error      TEXT NOT NULL DEFAULT ''
);

-- Relay claim path: unpublished rows ordered by next attempt.
CREATE INDEX idx_event_outbox_unpublished
    ON event_outbox (next_attempt_at) WHERE published_at IS NULL;
-- History/debug path: per-tenant event history by type.
CREATE INDEX idx_event_outbox_org_type
    ON event_outbox (organization_id, type, recorded_at);

-- ---------------------------------------------------------------------------
-- Durable correlation jobs: feed completion, manual sweeps and search-action
-- runs enqueue work here instead of spawning goroutines; workers claim rows
-- with a lease so a crashed worker's job is retried after the lease expires.
CREATE TABLE IF NOT EXISTS correlation_jobs (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    kind            TEXT NOT NULL,
    payload         JSONB NOT NULL DEFAULT '{}',
    state           TEXT NOT NULL DEFAULT 'pending',
    attempts        INT NOT NULL DEFAULT 0,
    lease_until     TIMESTAMPTZ,
    idempotency_key TEXT,
    last_error      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_correlation_jobs_idem
    ON correlation_jobs (idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX idx_correlation_jobs_claim
    ON correlation_jobs (created_at) WHERE state IN ('pending', 'running');

-- ---------------------------------------------------------------------------
-- Alert destinations: in-app and webhook channels. The webhook signing
-- secret is stored server-side and only ever returned masked.
CREATE TABLE IF NOT EXISTS alert_destinations (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    kind            TEXT NOT NULL DEFAULT 'webhook',
    name            TEXT NOT NULL,
    url             TEXT NOT NULL DEFAULT '',
    secret          TEXT NOT NULL DEFAULT '',
    events          TEXT[] NOT NULL DEFAULT '{}',
    min_severity    TEXT NOT NULL DEFAULT 'low',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_success_at TIMESTAMPTZ,
    last_error      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_alert_destinations_org ON alert_destinations (organization_id);

-- ---------------------------------------------------------------------------
-- Alert triggers: organization-scoped rules with a typed condition AST
-- (event triggers) or a metric threshold definition (device_metric).
CREATE TABLE IF NOT EXISTS alert_triggers (
    id                  UUID PRIMARY KEY,
    organization_id     UUID NOT NULL,
    name                TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    kind                TEXT NOT NULL,
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    lifecycle           TEXT NOT NULL DEFAULT 'stable',
    severity            TEXT NOT NULL DEFAULT 'medium',
    scope               JSONB NOT NULL DEFAULT '{}',
    conditions          JSONB NOT NULL DEFAULT '{}',
    event_types         TEXT[] NOT NULL DEFAULT '{}',
    recovery_event_types TEXT[] NOT NULL DEFAULT '{}',
    metric_field        TEXT NOT NULL DEFAULT '',
    aggregation         TEXT NOT NULL DEFAULT 'avg',
    operator            TEXT NOT NULL DEFAULT 'gt',
    threshold           DOUBLE PRECISION NOT NULL DEFAULT 0,
    window_secs         INT NOT NULL DEFAULT 300,
    group_by            TEXT NOT NULL DEFAULT 'asset',
    activation_secs     INT NOT NULL DEFAULT 0,
    recovery_secs       INT NOT NULL DEFAULT 300,
    recovery_threshold  DOUBLE PRECISION,
    missing_data_policy TEXT NOT NULL DEFAULT 'ignore',
    cooldown_secs       INT NOT NULL DEFAULT 300,
    repeat_secs         INT NOT NULL DEFAULT 0,
    destination_ids     TEXT[] NOT NULL DEFAULT '{}',
    revision            INT NOT NULL DEFAULT 1,
    created_by          TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_evaluated_at   TIMESTAMPTZ,
    last_error          TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_alert_triggers_org ON alert_triggers (organization_id);
CREATE INDEX idx_alert_triggers_enabled ON alert_triggers (enabled) WHERE enabled;

-- One evaluation state per (trigger, scope entity): activation timers,
-- hysteresis and last seen event live here. version is bumped on every
-- update for optimistic conflict detection.
CREATE TABLE IF NOT EXISTS alert_rule_states (
    trigger_id         UUID NOT NULL,
    scope_key          TEXT NOT NULL,
    organization_id    UUID NOT NULL,
    state              TEXT NOT NULL DEFAULT 'normal',
    pending_since      TIMESTAMPTZ,
    last_value         DOUBLE PRECISION,
    last_evaluated_at  TIMESTAMPTZ,
    last_transition_at TIMESTAMPTZ,
    last_event_id      TEXT NOT NULL DEFAULT '',
    version            BIGINT NOT NULL DEFAULT 1,
    PRIMARY KEY (trigger_id, scope_key)
);

-- ---------------------------------------------------------------------------
-- Occurrences: one row per alert episode. The partial unique index is the
-- database-level guarantee that a duplicate/replayed event can never open
-- a second open occurrence for the same rule and fingerprint.
CREATE TABLE IF NOT EXISTS alert_occurrences (
    id               UUID PRIMARY KEY,
    organization_id  UUID NOT NULL,
    trigger_id       UUID NOT NULL,
    fingerprint      TEXT NOT NULL,
    state            TEXT NOT NULL DEFAULT 'firing',
    severity         TEXT NOT NULL,
    title            TEXT NOT NULL,
    summary          TEXT NOT NULL DEFAULT '',
    site_id          UUID,
    asset_id         UUID,
    entity_type      TEXT NOT NULL DEFAULT '',
    entity_id        TEXT NOT NULL DEFAULT '',
    snapshot         JSONB NOT NULL DEFAULT '{}',
    evidence         JSONB NOT NULL DEFAULT '[]',
    occurrence_count INT NOT NULL DEFAULT 1,
    opened_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_at  TIMESTAMPTZ,
    recovered_at     TIMESTAMPTZ,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_alert_occurrences_open
    ON alert_occurrences (trigger_id, fingerprint)
    WHERE state IN ('firing', 'acknowledged');
CREATE INDEX idx_alert_occurrences_org_state
    ON alert_occurrences (organization_id, state, opened_at DESC);
CREATE INDEX idx_alert_occurrences_trigger
    ON alert_occurrences (trigger_id, opened_at DESC);

-- Append-only lifecycle history of every occurrence.
CREATE TABLE IF NOT EXISTS alert_transitions (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    occurrence_id   UUID NOT NULL,
    from_state      TEXT NOT NULL DEFAULT '',
    to_state        TEXT NOT NULL,
    event_id        TEXT NOT NULL DEFAULT '',
    observed_value  DOUBLE PRECISION,
    actor           TEXT NOT NULL DEFAULT 'system',
    reason          TEXT NOT NULL DEFAULT '',
    request_id      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_alert_transitions_occ ON alert_transitions (occurrence_id, created_at);

-- Per occurrence/destination delivery attempts with exponential retry and
-- a dead state; the unique idempotency key makes redelivery harmless.
CREATE TABLE IF NOT EXISTS alert_deliveries (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    occurrence_id   UUID NOT NULL,
    destination_id  UUID NOT NULL,
    transition_id   UUID,
    kind            TEXT NOT NULL DEFAULT 'fired',
    status          TEXT NOT NULL DEFAULT 'pending',
    attempts        INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_status_code INT,
    last_error      TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT NOT NULL,
    payload         JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at         TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_alert_deliveries_idem ON alert_deliveries (idempotency_key);
CREATE INDEX idx_alert_deliveries_due
    ON alert_deliveries (next_attempt_at) WHERE status IN ('pending', 'retry');
CREATE INDEX idx_alert_deliveries_occ ON alert_deliveries (occurrence_id, created_at);

-- ---------------------------------------------------------------------------
-- Vulnerability search actions: declarative local search plans.
CREATE TABLE IF NOT EXISTS vuln_search_actions (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    target_kind     TEXT NOT NULL DEFAULT 'software',
    selector        JSONB NOT NULL DEFAULT '{}',
    mode            TEXT NOT NULL DEFAULT 'shadow',
    priority        INT NOT NULL DEFAULT 100,
    enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    version_policy  JSONB NOT NULL DEFAULT '{}',
    confidence_cap  DOUBLE PRECISION NOT NULL DEFAULT 0.8,
    revision        INT NOT NULL DEFAULT 1,
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);

-- Immutable revision history: the canonical document is stored verbatim so
-- a run can always be explained against the exact definition it used.
CREATE TABLE IF NOT EXISTS vuln_search_action_revisions (
    id              UUID PRIMARY KEY,
    action_id       UUID NOT NULL,
    organization_id UUID NOT NULL,
    revision        INT NOT NULL,
    document        JSONB NOT NULL,
    hash            TEXT NOT NULL,
    reason          TEXT NOT NULL DEFAULT '',
    author          TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (action_id, revision)
);

CREATE TABLE IF NOT EXISTS vuln_search_runs (
    id               UUID PRIMARY KEY,
    organization_id  UUID NOT NULL,
    action_id        UUID NOT NULL,
    revision         INT NOT NULL,
    state            TEXT NOT NULL DEFAULT 'pending',
    progress         INT NOT NULL DEFAULT 0,
    requester        TEXT NOT NULL DEFAULT '',
    idempotency_key  TEXT,
    candidates       INT NOT NULL DEFAULT 0,
    matches          INT NOT NULL DEFAULT 0,
    findings_created INT NOT NULL DEFAULT 0,
    errors           JSONB NOT NULL DEFAULT '[]',
    started_at       TIMESTAMPTZ,
    finished_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_vuln_search_runs_idem
    ON vuln_search_runs (idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX idx_vuln_search_runs_action ON vuln_search_runs (action_id, created_at DESC);

-- Why each match exists: the action revision, local source, CPE/advisory
-- key, observed identity and the version projection that decided it.
CREATE TABLE IF NOT EXISTS vuln_match_provenance (
    id                UUID PRIMARY KEY,
    organization_id   UUID NOT NULL,
    finding_id        UUID NOT NULL,
    action_id         UUID,
    revision          INT,
    run_id            UUID,
    target_type       TEXT NOT NULL,
    target_id         UUID NOT NULL,
    origin            TEXT NOT NULL DEFAULT 'configured',
    source            TEXT NOT NULL,
    cpe_key           TEXT NOT NULL DEFAULT '',
    match_type        TEXT NOT NULL DEFAULT '',
    confidence        DOUBLE PRECISION NOT NULL DEFAULT 0,
    observed_identity JSONB NOT NULL DEFAULT '{}',
    reason            TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_vuln_match_provenance_finding ON vuln_match_provenance (finding_id);
CREATE INDEX idx_vuln_match_provenance_target ON vuln_match_provenance (target_type, target_id);

-- Operator-curated identity mappings (observed package/service name to a
-- canonical CPE or ecosystem identity) used to raise match confidence for
-- products the automatic resolver cannot pin.
CREATE TABLE IF NOT EXISTS vuln_identity_aliases (
    id                 UUID PRIMARY KEY,
    organization_id    UUID NOT NULL,
    name               TEXT NOT NULL,
    vendor             TEXT NOT NULL DEFAULT '',
    product            TEXT NOT NULL DEFAULT '',
    ecosystem          TEXT NOT NULL DEFAULT '',
    canonical_part     TEXT NOT NULL DEFAULT 'a',
    canonical_vendor   TEXT NOT NULL DEFAULT '',
    canonical_product  TEXT NOT NULL DEFAULT '',
    canonical_ecosystem TEXT NOT NULL DEFAULT '',
    confidence         DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    reason             TEXT NOT NULL DEFAULT '',
    created_by         TEXT NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name, vendor, product)
);
