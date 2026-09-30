-- F6 (finding handoff to a tracker): where the work went, and F4/F10's
-- shared per-org integration settings. One row per (org, kind); the secret
-- column holds the API token and follows the existing plaintext-secret
-- convention of this codebase (connectors.config, alert_destinations.secret).
CREATE TABLE IF NOT EXISTS org_integrations (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,
    config          JSONB NOT NULL DEFAULT '{}'::jsonb,
    secret          TEXT NOT NULL DEFAULT '',
    created_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, kind)
);

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS external_tracker TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS external_key TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS external_url TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS external_synced_at TIMESTAMPTZ;
