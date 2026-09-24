-- Link hub scanners to their owning connector record (aegis.connector.v1).
-- A connector of kind=scanner OWNS one scanners row: enrollment of the
-- connector materializes the row, the hub Jobs stream drives its health,
-- and deleting the connector cascades the row away. Legacy token-enrolled
-- scanners keep connector_id NULL.
ALTER TABLE scanners
    ADD COLUMN IF NOT EXISTS connector_id UUID REFERENCES connectors(id) ON DELETE CASCADE;

-- One scanner row per connector.
CREATE UNIQUE INDEX IF NOT EXISTS uq_scanners_connector
    ON scanners(connector_id) WHERE connector_id IS NOT NULL;
