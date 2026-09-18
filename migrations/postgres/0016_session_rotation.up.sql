-- 0016: rotating refresh tokens with reuse detection.
--
-- Sessions switch from "one long-lived refresh JWT per login" to opaque
-- rotating refresh tokens: every successful refresh rotates the stored
-- hash. The retired hashes are kept in a small JSONB ledger with their
-- retirement timestamps so that
--   * concurrent refreshes (multi-tab, 401 retry waves) presenting a
--     just-retired token inside a short grace window keep working, and
--   * presenting a retired token AFTER the grace window is reuse of a
--     possibly-stolen token and revokes the whole session family.
--
-- The rotation UPDATE retires the row's CURRENT hash atomically at write
-- time (row locks serialize rotations; the SET clause re-reads the latest
-- row version), so the token last written into a browser's shared cookie
-- jar is always either the current hash or a retired-within-grace hash —
-- there is no interleave that strands a tab.
--
-- Session lookup now goes by the presented token's hash (opaque tokens
-- carry no session id claim), hence the GIN index.

ALTER TABLE sessions
    ADD COLUMN retired JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE sessions
    ADD COLUMN rotated_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE INDEX idx_sessions_refresh_hash ON sessions(refresh_hash);
CREATE INDEX idx_sessions_retired ON sessions USING gin(retired);
