-- 0019: unified external connector registry (v1.4.0). Every externally
-- connected component — endpoint agents, remote scanners, external
-- collectors — is created here from the UI and enrolls over gRPC
-- (service aegis.connector.v1.ConnectorService) with a one-time token,
-- then keeps working with a long-lived secret (stored hashed).
--
-- kind            : agent | scanner | collector
-- status          : pending  (created, never enrolled)
--                   active   (enrolled; online iff last_seen is fresh)
--                   revoked  (secret invalidated, connections rejected)
-- config          : free-form role configuration edited from the UI
-- config_version  : monotonic; bumped on every config change, pushed to
--                   live WatchConfig streams for hot reload
-- secret_hash     : sha256 of the connector secret; empty until enrolled

CREATE TABLE connectors (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    site_id         UUID REFERENCES sites(id) ON DELETE SET NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('agent','scanner','collector')),
    name            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','active','revoked')),
    hostname        TEXT NOT NULL DEFAULT '',
    platform        TEXT NOT NULL DEFAULT '',
    arch            TEXT NOT NULL DEFAULT '',
    version         TEXT NOT NULL DEFAULT '',
    capabilities    JSONB NOT NULL DEFAULT '[]'::jsonb,
    config          JSONB NOT NULL DEFAULT '{}'::jsonb,
    config_version  BIGINT NOT NULL DEFAULT 1,
    secret_hash     TEXT NOT NULL DEFAULT '',
    enrolled_at     TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    last_status     JSONB,
    created_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_connectors_org      ON connectors(organization_id, kind);
CREATE INDEX idx_connectors_seen     ON connectors(last_seen DESC);
CREATE INDEX idx_connectors_status   ON connectors(organization_id, status);

-- One-time enrollment tokens. Each row is pre-bound to the connector it
-- unlocks; used_at burns the token so replayed init attempts fail.
CREATE TABLE connector_enroll_tokens (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    connector_id    UUID NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,   -- sha256 of the bearer token
    created_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    revoked         BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX idx_conn_tokens_connector ON connector_enroll_tokens(connector_id, created_at DESC);
CREATE INDEX idx_conn_tokens_org       ON connector_enroll_tokens(organization_id);
