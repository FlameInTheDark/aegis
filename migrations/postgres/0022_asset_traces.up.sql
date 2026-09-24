-- Per-target traceroute evidence (v1.5.6): the parsed hop path plus the RAW
-- probe output (nmap XML / tracert text) so asset views can show what the
-- scanner actually observed — and so any hop address can be queried for the
-- list of traces that cover it (routers, gateways, intermediate hops).
CREATE TABLE asset_traces (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    site_id         UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    scan_id         TEXT NOT NULL DEFAULT '',
    target_ip       TEXT NOT NULL,
    method          TEXT NOT NULL DEFAULT 'traceroute',
    probe           TEXT NOT NULL DEFAULT '',
    complete        BOOLEAN NOT NULL DEFAULT false,
    hops_count      INT NOT NULL DEFAULT 0,
    path            JSONB NOT NULL DEFAULT '[]'::jsonb,
    hop_ips         TEXT[] NOT NULL DEFAULT '{}',
    raw             TEXT NOT NULL DEFAULT '',
    confidence      REAL NOT NULL DEFAULT 0.85,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (site_id, target_ip)
);
CREATE INDEX idx_asset_traces_org ON asset_traces(organization_id);
CREATE INDEX idx_asset_traces_site ON asset_traces(site_id);
-- Coverage lookup: every trace whose path touches an asset address.
CREATE INDEX idx_asset_traces_hop_ips ON asset_traces USING gin (hop_ips);
