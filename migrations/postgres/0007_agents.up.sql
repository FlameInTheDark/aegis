-- 0007: endpoint agents — device identity, typed tasks, enrollment tokens
-- (spec §16, §19). Private keys are never stored.

CREATE TABLE agents (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    site_id         UUID REFERENCES sites(id) ON DELETE SET NULL,
    asset_id        UUID REFERENCES assets(id) ON DELETE SET NULL,
    hostname        TEXT NOT NULL DEFAULT '',
    platform        TEXT NOT NULL DEFAULT '' CHECK (platform IN ('windows','linux','darwin','')),
    platform_version TEXT NOT NULL DEFAULT '',
    arch            TEXT NOT NULL DEFAULT '',
    agent_version   TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'offline'
                    CHECK (status IN ('online','offline','degraded')),
    cert_serial     TEXT NOT NULL DEFAULT '',
    cert_not_after  TIMESTAMPTZ,
    capabilities    TEXT[] NOT NULL DEFAULT '{}',
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    enrolled_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked         BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX idx_agents_org  ON agents(organization_id);
CREATE INDEX idx_agents_site ON agents(site_id);
CREATE INDEX idx_agents_seen ON agents(last_seen DESC);

CREATE TABLE agent_tasks (
    id          UUID PRIMARY KEY,
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    type        TEXT NOT NULL CHECK (type IN
                ('inventory_refresh','software_inventory','network_inventory','socket_inventory',
                 'security_posture','local_configuration_check','local_scan','diagnostic','configuration_sync')),
    issued_by   UUID NOT NULL,
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    args        JSONB NOT NULL DEFAULT '{}'::jsonb,
    state       TEXT NOT NULL DEFAULT 'pending'
                CHECK (state IN ('pending','delivered','running','succeeded','failed','expired')),
    result      JSONB,
    error       TEXT
);
CREATE INDEX idx_agent_tasks_agent ON agent_tasks(agent_id, issued_at DESC);
CREATE INDEX idx_agent_tasks_state ON agent_tasks(state);

CREATE TABLE enrollment_tokens (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    site_id         UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,    -- sha256 of the bearer token
    prefix          TEXT NOT NULL DEFAULT '',
    created_by      UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    revoked         BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX idx_enroll_org ON enrollment_tokens(organization_id, created_at DESC);

CREATE TABLE agent_events (
    id          UUID PRIMARY KEY,
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,
    payload     JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_agent_events_agent ON agent_events(agent_id, occurred_at DESC);
