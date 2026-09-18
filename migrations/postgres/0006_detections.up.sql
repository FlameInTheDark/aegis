-- 0006: detection engine — typed rules (Sigma-compatible metadata), matches
-- and statistical baselines (spec §40, §41, §189).

CREATE TABLE detection_rules (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    title           TEXT NOT NULL,
    identifier      TEXT NOT NULL,       -- stable Sigma-like uuid
    status          TEXT NOT NULL DEFAULT 'stable'
                    CHECK (status IN ('stable','experimental','disabled')),
    description     TEXT NOT NULL DEFAULT '',
    refs            TEXT[] NOT NULL DEFAULT '{}',
    author          TEXT NOT NULL DEFAULT '',
    tags            TEXT[] NOT NULL DEFAULT '{}',
    logsource       JSONB NOT NULL DEFAULT '{}'::jsonb,
    level           TEXT NOT NULL DEFAULT 'medium'
                    CHECK (level IN ('info','low','medium','high','critical')),
    false_positives TEXT[] NOT NULL DEFAULT '{}',
    type            TEXT NOT NULL
                    CHECK (type IN ('single_event','threshold','temporal','sequence','entity_agg')),
    event_type      TEXT NOT NULL DEFAULT '',
    conditions      JSONB NOT NULL DEFAULT '[]'::jsonb,
    threshold       JSONB,
    window_spec     TEXT NOT NULL DEFAULT '',
    group_by        TEXT[] NOT NULL DEFAULT '{}',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, identifier)
);
CREATE INDEX idx_rules_org_enabled ON detection_rules(organization_id, enabled);

CREATE TABLE detection_matches (
    id         UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    rule_id    UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    rule_title TEXT NOT NULL DEFAULT '',
    level      TEXT NOT NULL DEFAULT 'medium',
    site_id    UUID,
    asset_id   UUID,
    src_ip     INET,
    entity     TEXT NOT NULL DEFAULT '',
    summary    TEXT NOT NULL,
    event_ids  TEXT[] NOT NULL DEFAULT '{}',
    count      INTEGER NOT NULL DEFAULT 1,
    timeline   JSONB,
    timestamp  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_matches_org_time ON detection_matches(organization_id, timestamp DESC);
CREATE INDEX idx_matches_rule     ON detection_matches(rule_id, timestamp DESC);
CREATE INDEX idx_matches_level    ON detection_matches(level, timestamp DESC);

CREATE TABLE baselines (
    entity      TEXT NOT NULL,
    metric      TEXT NOT NULL,
    mean        DOUBLE PRECISION NOT NULL DEFAULT 0,
    stddev      DOUBLE PRECISION NOT NULL DEFAULT 0,
    sample_size INTEGER NOT NULL DEFAULT 0,
    window_days INTEGER NOT NULL DEFAULT 14,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (entity, metric)
);

CREATE TABLE webhook_configs (
    id         UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    url        TEXT NOT NULL,
    events     TEXT[] NOT NULL DEFAULT '{}',
    enabled    BOOLEAN NOT NULL DEFAULT true,
    last_fired TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);
