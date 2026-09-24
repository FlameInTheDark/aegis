-- Analyst-defined asset groups (v1.13.0): user-curated grouping of assets by
-- location, function, owner or any custom scheme. Groups carry presentation
-- metadata (color key, icon key) the UI renders as chips/filters; membership
-- is a plain join table so one asset can live in several groups.
CREATE TABLE asset_groups (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    color           TEXT NOT NULL DEFAULT 'slate',
    icon            TEXT NOT NULL DEFAULT 'boxes',
    kind            TEXT NOT NULL DEFAULT 'custom',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);
CREATE INDEX idx_asset_groups_org ON asset_groups(organization_id);

CREATE TABLE asset_group_members (
    group_id UUID NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, asset_id)
);
CREATE INDEX idx_asset_group_members_asset ON asset_group_members(asset_id);
