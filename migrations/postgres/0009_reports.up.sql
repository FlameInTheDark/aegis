-- 0009: reporting — definitions, jobs, artifacts (spec §50, §138).

CREATE TABLE reports (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    type            TEXT NOT NULL CHECK (type IN
                    ('executive_security','technical_vulnerability','network_inventory','topology',
                     'security_event','asset_risk','scan_comparison')),
    format          TEXT NOT NULL CHECK (format IN ('pdf','html','csv','json')),
    site_id         UUID,
    scan_id         UUID,
    date_from       TIMESTAMPTZ,
    date_to         TIMESTAMPTZ,
    sections        TEXT[] NOT NULL DEFAULT '{}',
    min_severity    TEXT,
    created_by      UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_reports_org ON reports(organization_id, created_at DESC);

CREATE TABLE report_jobs (
    id          UUID PRIMARY KEY,
    definition_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL,
    state       TEXT NOT NULL DEFAULT 'queued'
                CHECK (state IN ('queued','running','completed','failed')),
    progress    REAL NOT NULL DEFAULT 0,
    artifact_key TEXT NOT NULL DEFAULT '',
    size_bytes  BIGINT NOT NULL DEFAULT 0,
    error       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);
CREATE INDEX idx_report_jobs_org ON report_jobs(organization_id, created_at DESC);
