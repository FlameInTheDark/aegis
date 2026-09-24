-- 0032: analyst topology parent override.
--
-- Layer-2 switches are invisible to network scans: they forward frames
-- without a routable hop, so traceroute shows hosts behind them as direct
-- children of the router. The switch itself still surfaces in the inventory
-- (a management web interface, a responding MAC vendor, an ARP entry), so
-- the analyst knows the real wiring — this column lets them state it.
--
-- Like the identity overrides (0031) it is NEVER written by scan ingestion:
-- the evidence-derived topology stays untouched, and clearing the override
-- (NULL) returns the node to its evidence-derived position. ON DELETE SET
-- NULL keeps the column valid when the parent asset is removed; the check
-- below rejects the trivial self-parent.
--
-- The write path (PATCH /assets/:id) additionally enforces same-organization
-- references and walks the existing override chain to reject cycles; the
-- topology page turns the column into a confidence-1.0 parent edge that
-- always wins over inferred evidence (cycle-safe there too).

ALTER TABLE assets ADD COLUMN IF NOT EXISTS parent_override UUID
    REFERENCES assets(id) ON DELETE SET NULL;
ALTER TABLE assets ADD CONSTRAINT assets_parent_override_not_self
    CHECK (parent_override IS NULL OR parent_override <> id);
