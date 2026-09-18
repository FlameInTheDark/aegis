-- 0001: tenancy core — organizations, users, memberships, teams, sites,
-- networks, audit log. All tenant-owned tables carry organization_id so
-- isolation can be enforced at the repository layer (spec §84).

CREATE TABLE organizations (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id            UUID PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,            -- argon2id PHC string
    disabled      BOOLEAN NOT NULL DEFAULT false,
    last_login_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
    id              UUID PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role            TEXT NOT NULL CHECK (role IN ('owner','administrator','security_analyst','operator','viewer')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, organization_id)
);
CREATE INDEX idx_memberships_user ON memberships(user_id);
CREATE INDEX idx_memberships_org  ON memberships(organization_id);

CREATE TABLE teams (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);

CREATE TABLE team_members (
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (team_id, user_id)
);

CREATE TABLE sessions (
    id              UUID PRIMARY KEY,          -- matches JWT sid claim
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL,
    refresh_hash    TEXT NOT NULL,
    ip              TEXT,
    user_agent      TEXT,
    revoked         BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

CREATE TABLE sites (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    site_type       TEXT NOT NULL DEFAULT 'branch'
                    CHECK (site_type IN ('hq','datacenter','cloud','branch','home','lab')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);
CREATE INDEX idx_sites_org ON sites(organization_id);

CREATE TABLE networks (
    id              UUID PRIMARY KEY,
    site_id         UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    cidr            CIDR NOT NULL,
    vlan_id         INTEGER,
    name            TEXT NOT NULL DEFAULT '',
    gateway         INET,
    exposure        TEXT NOT NULL DEFAULT 'internal_only'
                    CHECK (exposure IN ('internal_only','vpn_only','publicly_reachable','unknown')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (site_id, cidr)
);
CREATE INDEX idx_networks_site ON networks(site_id);
CREATE INDEX idx_networks_org  ON networks(organization_id);

CREATE TABLE audit_logs (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    actor_id        UUID,
    actor_name      TEXT,
    actor_ip        TEXT,
    action          TEXT NOT NULL,
    target          TEXT,
    site_id         UUID,
    before_state    JSONB,
    after_state     JSONB,
    result          TEXT NOT NULL DEFAULT 'success',
    detail          JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_org_time ON audit_logs(organization_id, created_at DESC);
CREATE INDEX idx_audit_actor    ON audit_logs(actor_id, created_at DESC);
CREATE INDEX idx_audit_action   ON audit_logs(action);
