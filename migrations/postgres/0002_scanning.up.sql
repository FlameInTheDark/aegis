-- 0002: scanning — profiles, scans, scopes, tasks, observations, scanners,
-- schedules and change detection (spec §11, §68, §69, §26).

CREATE TABLE scan_profiles (
    name        TEXT PRIMARY KEY,      -- discovery_safe|inventory|vulnerability_safe|active_validation
    description TEXT NOT NULL DEFAULT '',
    spec        JSONB NOT NULL         -- ProfileDefinition snapshot for reproducibility
);

CREATE TABLE scanners (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    site_id         UUID REFERENCES sites(id) ON DELETE SET NULL,
    name            TEXT NOT NULL,
    version         TEXT NOT NULL DEFAULT '',
    capabilities    TEXT[] NOT NULL DEFAULT '{}',
    interfaces      TEXT[] NOT NULL DEFAULT '{}',
    health          TEXT NOT NULL DEFAULT 'offline' CHECK (health IN ('healthy','degraded','offline')),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);
CREATE INDEX idx_scanners_site ON scanners(site_id);

CREATE TABLE scans (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    site_id         UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    profile         TEXT NOT NULL REFERENCES scan_profiles(name),
    engine          TEXT NOT NULL DEFAULT 'nmap',
    scanner_id      UUID REFERENCES scanners(id) ON DELETE SET NULL,
    created_by      UUID,
    state           TEXT NOT NULL DEFAULT 'queued'
                    CHECK (state IN ('queued','running','paused','cancelling','completed','failed','cancelled')),
    progress        REAL NOT NULL DEFAULT 0,
    phase           TEXT NOT NULL DEFAULT '',
    config          JSONB,                 -- exact reproducible ScanConfig
    stats           JSONB NOT NULL DEFAULT '{}'::jsonb,
    error           TEXT,
    kill_switch     BOOLEAN NOT NULL DEFAULT false,
    scheduled       BOOLEAN NOT NULL DEFAULT false,
    schedule_cron   TEXT,
    idempotency_key TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ
);
CREATE INDEX idx_scans_org_created ON scans(organization_id, created_at DESC);
CREATE INDEX idx_scans_site_state  ON scans(site_id, state);
CREATE UNIQUE INDEX idx_scans_idem ON scans(idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE TABLE scan_scopes (
    id            UUID PRIMARY KEY,
    scan_id       UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cidrs         TEXT[] NOT NULL DEFAULT '{}',
    ip_ranges     TEXT[] NOT NULL DEFAULT '{}',
    hostnames     TEXT[] NOT NULL DEFAULT '{}',
    allowlist     TEXT[] NOT NULL DEFAULT '{}',
    denylist      TEXT[] NOT NULL DEFAULT '{}',
    exclude_hosts TEXT[] NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_scan_scopes_scan ON scan_scopes(scan_id);

CREATE TABLE scan_tasks (
    id          UUID PRIMARY KEY,
    scan_id     UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,
    state       TEXT NOT NULL DEFAULT 'pending'
                CHECK (state IN ('pending','dispatched','running','succeeded','failed','retrying','cancelled')),
    scanner_id  UUID,
    target      TEXT,
    attempt     INTEGER NOT NULL DEFAULT 0,
    payload     BYTEA,
    error       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);
CREATE INDEX idx_scan_tasks_scan_state ON scan_tasks(scan_id, state);

CREATE TABLE scan_observations (
    id              UUID PRIMARY KEY,
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    task_id         UUID,
    site_id         UUID NOT NULL,
    organization_id UUID NOT NULL,
    target          TEXT NOT NULL,
    observation_type TEXT NOT NULL,
    observed_at     TIMESTAMPTZ NOT NULL,
    source          TEXT NOT NULL,
    payload         BYTEA,
    normalized      JSONB,
    confidence      REAL NOT NULL DEFAULT 0.5,
    error           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Declarative partitioning candidates (spec §77); range partitioning added
-- operationally when volume warrants. Keep a hot index for now:
CREATE INDEX idx_scan_obs_scan ON scan_observations(scan_id, observed_at DESC);
CREATE INDEX idx_scan_obs_type ON scan_observations(observation_type, observed_at DESC);

CREATE TABLE scan_schedules (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    site_id         UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    profile         TEXT NOT NULL REFERENCES scan_profiles(name),
    cron            TEXT NOT NULL,
    scope           TEXT[] NOT NULL DEFAULT '{}',
    engine          TEXT NOT NULL DEFAULT 'nmap',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_by      UUID,
    last_run_at     TIMESTAMPTZ,
    next_run_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_schedules_next ON scan_schedules(enabled, next_run_at);

CREATE TABLE scan_changes (
    id              UUID PRIMARY KEY,
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    site_id         UUID NOT NULL,
    type            TEXT NOT NULL,
    asset_id        UUID,
    entity          TEXT,
    before_value    TEXT,
    after_value     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_changes_site_time ON scan_changes(site_id, created_at DESC);
CREATE INDEX idx_changes_scan      ON scan_changes(scan_id);
