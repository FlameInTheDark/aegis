ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_parent_override_not_self;
ALTER TABLE assets DROP COLUMN IF EXISTS parent_override;
