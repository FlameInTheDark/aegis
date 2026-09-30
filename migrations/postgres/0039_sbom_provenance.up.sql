-- F8 (SBOM as an inventory source): provenance for the CycloneDX document
-- an operator uploaded for an asset. The digest identifies the exact BOM
-- that produced the source='sbom' software rows.
ALTER TABLE assets ADD COLUMN IF NOT EXISTS sbom_digest TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN IF NOT EXISTS sbom_uploaded_at TIMESTAMPTZ;
