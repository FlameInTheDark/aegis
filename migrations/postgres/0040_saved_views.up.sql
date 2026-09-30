-- F12 (saved views): named query-string views stored per user. A view is
-- the hash-router query string of one console page (assets|findings|alerts);
-- sharing inside the org is a later flag on the same row.
CREATE TABLE IF NOT EXISTS saved_views (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    page            TEXT NOT NULL,
    name            TEXT NOT NULL,
    query           TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, page, name)
);
CREATE INDEX IF NOT EXISTS idx_saved_views_user_page ON saved_views (user_id, page);
