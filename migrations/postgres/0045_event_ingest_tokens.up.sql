-- F11 (sensor setup that finishes in the console): hashed, revocable,
-- audited ingest tokens. Sensors authenticate to POST /ingest/events with
-- 'Bearer aeg_evt_...' — the plaintext is shown once at creation, only the
-- SHA-256 hash is stored.
CREATE TABLE IF NOT EXISTS event_ingest_tokens (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    token_hash      TEXT NOT NULL UNIQUE,
    prefix          TEXT NOT NULL DEFAULT '',
    created_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_ingest_tokens_org ON event_ingest_tokens (organization_id, revoked_at);
