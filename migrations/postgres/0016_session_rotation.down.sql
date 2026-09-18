-- 0016 (down): revert to non-rotating sessions.

DROP INDEX IF EXISTS idx_sessions_retired;
DROP INDEX IF EXISTS idx_sessions_refresh_hash;

ALTER TABLE sessions
    DROP COLUMN IF EXISTS rotated_at;

ALTER TABLE sessions
    DROP COLUMN IF EXISTS retired;
