-- Cross-replica singleton lease for feed syncs. Helm runs one feed-worker
-- replica, but a second replica (or a forgotten local worker) pointing at
-- the same database previously double-pulled NVD. The lease is a timestamp
-- next to the feed status: an expired lease needs no cleanup pass, so a
-- crashed worker self-heals after the TTL.
ALTER TABLE feed_sources ADD COLUMN IF NOT EXISTS lease_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE feed_sources ADD COLUMN IF NOT EXISTS lease_until TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01T00:00:00Z'::timestamptz;
