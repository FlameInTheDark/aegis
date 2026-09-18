-- 0004: vulnerability intelligence — CVE store, CPE matches, EPSS, KEV,
-- references, source provenance, OSV records, feed bookkeeping
-- (spec §27-§36, §115).

CREATE TABLE vulnerabilities (
    cve_id         TEXT PRIMARY KEY,          -- canonical CVE-YYYY-NNNN
    state          TEXT NOT NULL DEFAULT 'PUBLISHED'
                   CHECK (state IN ('PUBLISHED','REJECTED','RESERVED','DISPUTED')),
    published_at   TIMESTAMPTZ,
    updated_at     TIMESTAMPTZ,
    description    TEXT NOT NULL DEFAULT '',
    cvss_v2        JSONB,
    cvss_v3        JSONB,
    cvss_v4        JSONB,
    cwe            TEXT[] NOT NULL DEFAULT '{}',
    source         TEXT NOT NULL,             -- nvd | cve | osv | manual
    source_record  TEXT NOT NULL DEFAULT '',
    source_version TEXT NOT NULL DEFAULT '',
    ingested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    raw_ref        TEXT NOT NULL DEFAULT ''   -- object storage key of raw JSON
);
CREATE INDEX idx_vulns_published ON vulnerabilities(published_at DESC);
CREATE INDEX idx_vulns_source    ON vulnerabilities(source);

CREATE TABLE vulnerability_cpe_matches (
    id                  UUID PRIMARY KEY,
    cve_id              TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    cpe                 TEXT NOT NULL,       -- cpe:2.3:part:vendor:product:version:...
    vendor              TEXT NOT NULL DEFAULT '',
    product             TEXT NOT NULL DEFAULT '',
    version             TEXT NOT NULL DEFAULT '',
    version_start_incl  TEXT NOT NULL DEFAULT '',
    version_start_excl  TEXT NOT NULL DEFAULT '',
    version_end_incl    TEXT NOT NULL DEFAULT '',
    version_end_excl    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_cpe_matches_cve     ON vulnerability_cpe_matches(cve_id);
CREATE INDEX idx_cpe_matches_product ON vulnerability_cpe_matches(vendor, product);

CREATE TABLE vulnerability_references (
    id       UUID PRIMARY KEY,
    cve_id   TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    url      TEXT NOT NULL,
    tags     TEXT[] NOT NULL DEFAULT '{}',
    source   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_vuln_refs_cve ON vulnerability_references(cve_id);

CREATE TABLE vulnerability_epss (
    cve_id     TEXT NOT NULL,
    date       DATE NOT NULL,
    epss       DOUBLE PRECISION NOT NULL,
    percentile DOUBLE PRECISION NOT NULL DEFAULT 0,
    source     TEXT NOT NULL DEFAULT 'first',
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (cve_id, date)
);
CREATE INDEX idx_epss_cve ON vulnerability_epss(cve_id, date DESC);

CREATE TABLE vulnerability_kev (
    cve_id           TEXT PRIMARY KEY,
    known_exploited  BOOLEAN NOT NULL DEFAULT true,
    date_added       TIMESTAMPTZ,
    due_date         TIMESTAMPTZ,
    ransomware_use   TEXT NOT NULL DEFAULT '',
    required_action  TEXT NOT NULL DEFAULT '',
    source           TEXT NOT NULL DEFAULT 'cisa_kev',
    ingested_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE vulnerability_sources (
    id           UUID PRIMARY KEY,
    cve_id       TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    source       TEXT NOT NULL,
    source_record_id TEXT NOT NULL DEFAULT '',
    source_version   TEXT NOT NULL DEFAULT '',
    source_updated_at TIMESTAMPTZ,
    field        TEXT NOT NULL DEFAULT '',     -- which normalized field this proves
    value        JSONB,
    ingested_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_vuln_sources_cve ON vulnerability_sources(cve_id);

CREATE TABLE osv_records (
    id          TEXT PRIMARY KEY,             -- OSV-... | GHSA-...
    cve_ids     TEXT[] NOT NULL DEFAULT '{}',
    summary     TEXT NOT NULL DEFAULT '',
    details     TEXT NOT NULL DEFAULT '',
    ecosystem   TEXT NOT NULL DEFAULT '',
    package_name TEXT NOT NULL DEFAULT '',
    severities  JSONB NOT NULL DEFAULT '[]'::jsonb,
    refs        JSONB NOT NULL DEFAULT '[]'::jsonb,
    affected_ranges JSONB NOT NULL DEFAULT '[]'::jsonb,
    published   TIMESTAMPTZ,
    modified    TIMESTAMPTZ,
    source      TEXT NOT NULL DEFAULT 'osv',
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_osv_package ON osv_records(ecosystem, package_name);
CREATE INDEX idx_osv_cves    ON osv_records USING gin(cve_ids);

CREATE TABLE feed_sources (
    name            TEXT PRIMARY KEY,   -- nvd|kev|epss|osv|vulnrichment|cve
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_sync_at    TIMESTAMPTZ,
    last_status     TEXT NOT NULL DEFAULT 'never_synced'
                    CHECK (last_status IN ('healthy','stale','failed','never_synced')),
    records_ingested BIGINT NOT NULL DEFAULT 0,
    records_new     BIGINT NOT NULL DEFAULT 0,
    records_updated BIGINT NOT NULL DEFAULT 0,
    last_error      TEXT,
    license         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE feed_sync_runs (
    id          UUID PRIMARY KEY,
    feed        TEXT NOT NULL REFERENCES feed_sources(name),
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    status      TEXT NOT NULL DEFAULT 'running'
                CHECK (status IN ('running','completed','failed','partial')),
    processed   BIGINT NOT NULL DEFAULT 0,
    created     BIGINT NOT NULL DEFAULT 0,
    updated     BIGINT NOT NULL DEFAULT 0,
    rejected    BIGINT NOT NULL DEFAULT 0,
    error       TEXT
);
CREATE INDEX idx_feed_runs_feed ON feed_sync_runs(feed, started_at DESC);
