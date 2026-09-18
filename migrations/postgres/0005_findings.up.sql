-- 0005: findings — vulnerability instances per asset/service with evidence,
-- status history and scoped suppressions (spec §38, §39, §93).

CREATE TABLE findings (
    id               UUID PRIMARY KEY,
    organization_id  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_id         UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    service_id       UUID REFERENCES services(id) ON DELETE CASCADE,
    software_id      UUID REFERENCES software(id) ON DELETE CASCADE,
    cve_id           TEXT REFERENCES vulnerabilities(cve_id),
    osv_id           TEXT,
    title            TEXT NOT NULL,
    match_type       TEXT NOT NULL
                     CHECK (match_type IN ('EXACT_CPE','CPE_RANGE','PACKAGE_VERSION','OS_PACKAGE','SERVICE_VERSION','HEURISTIC')),
    confidence       REAL NOT NULL DEFAULT 0.5,
    risk_score       REAL NOT NULL DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    severity         TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    status           TEXT NOT NULL DEFAULT 'open'
                     CHECK (status IN ('open','acknowledged','in_progress','resolved','accepted_risk','false_positive','suppressed')),
    owner            TEXT NOT NULL DEFAULT '',
    notes            TEXT NOT NULL DEFAULT '',
    remediation      TEXT NOT NULL DEFAULT '',
    suppressed_until TIMESTAMPTZ,
    first_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (asset_id, cve_id, service_id)
);
CREATE INDEX idx_findings_asset_vuln  ON findings(asset_id, status);
CREATE INDEX idx_findings_vuln_status ON findings(cve_id, status);
CREATE INDEX idx_findings_risk        ON findings(risk_score DESC);
CREATE INDEX idx_findings_first_seen  ON findings(first_seen DESC);
CREATE INDEX idx_findings_org_status  ON findings(organization_id, status);
CREATE INDEX idx_findings_severity    ON findings(severity, status);

-- NULL-safe dedup key: one finding per (asset, cve, service) triple even
-- when service is NULL.
CREATE UNIQUE INDEX idx_findings_dedup ON findings
    (asset_id, COALESCE(cve_id, ''), COALESCE(service_id::text, ''));

CREATE TABLE finding_evidence (
    id         UUID PRIMARY KEY,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    statement  TEXT NOT NULL,
    detail     JSONB,
    source     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_evidence_finding ON finding_evidence(finding_id);

CREATE TABLE finding_status_history (
    id         UUID PRIMARY KEY,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    from_state TEXT NOT NULL,
    to_state   TEXT NOT NULL,
    changed_by TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_status_hist_finding ON finding_status_history(finding_id, created_at DESC);

CREATE TABLE suppressions (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_id        UUID,
    service_id      UUID,
    vulnerability   TEXT,   -- CVE id
    site_id         UUID,
    tag             TEXT,
    reason          TEXT NOT NULL,
    created_by      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ
);
CREATE INDEX idx_suppressions_org ON suppressions(organization_id, expires_at);

CREATE TABLE notes (
    id         UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    entity     TEXT NOT NULL CHECK (entity IN ('asset','finding','detection','scan')),
    entity_id  UUID NOT NULL,
    author_id  UUID NOT NULL,
    author_name TEXT NOT NULL DEFAULT '',
    content    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_notes_entity ON notes(entity, entity_id, created_at DESC);
