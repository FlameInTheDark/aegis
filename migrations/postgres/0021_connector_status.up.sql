-- 0021: connector liveness semantics + scanner backfill.
--
-- shutdown_at : timestamp of the last heartbeat that reported
--               state="shutting_down" (graceful stop). The derived
--               connection state shows "shutting down" until this goes
--               stale (the connector's online window), then "offline".
--               Cleared (NULL) by the next heartbeat that reports
--               state="running".
ALTER TABLE connectors ADD COLUMN IF NOT EXISTS shutdown_at TIMESTAMPTZ;

-- Backfill: materialize the scanners row for every kind=scanner connector
-- that enrolled BEFORE the v1.5.0 unification (0020 links rows only at
-- enrollment time, so pre-existing connections never got one and were
-- invisible to the scan UI and the Settings scanners panel).
INSERT INTO scanners (id, organization_id, site_id, name, version,
                      capabilities, interfaces, health, last_seen,
                      transport, connector_id)
SELECT gen_random_uuid(), c.organization_id, c.site_id, c.name,
       COALESCE(c.version, ''),
       ARRAY['connector'], ARRAY[]::TEXT[], 'offline',
       COALESCE(c.last_seen, now()), 'connector', c.id
FROM connectors c
WHERE c.kind = 'scanner'
  AND NOT EXISTS (SELECT 1 FROM scanners s WHERE s.connector_id = c.id)
ON CONFLICT DO NOTHING; -- UNIQUE (organization_id, name) collision: the heartbeat cascade + hub auth retry EnsureForConnector later
