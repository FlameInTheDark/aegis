-- Reverse of 0033: drop the connector binding and restore the standalone
-- enrollment token table from 0007.

DROP INDEX IF EXISTS idx_agents_connector;
ALTER TABLE agents DROP COLUMN IF EXISTS connector_id;

CREATE TABLE enrollment_tokens (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    site_id         UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,
    prefix          TEXT NOT NULL DEFAULT '',
    created_by      UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    revoked         BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX idx_enroll_org ON enrollment_tokens(organization_id, created_at DESC);
