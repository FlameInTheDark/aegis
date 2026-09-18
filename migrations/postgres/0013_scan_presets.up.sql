-- 0013: custom nmap presets — org-scoped scan profiles created from Settings.
-- Built-ins keep is_builtin = true (default backfills existing rows);
-- custom presets are org-owned rows whose spec JSON carries the knobs and
-- the validated extra nmap arguments (ProfileDefinition.ExtraArgs).
ALTER TABLE scan_profiles ADD COLUMN is_builtin BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE scan_profiles ADD COLUMN org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
CREATE INDEX idx_scan_profiles_custom ON scan_profiles(org_id) WHERE is_builtin = false;
