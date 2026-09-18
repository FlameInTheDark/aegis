-- 0008: topology graph with evidence-backed edges (spec §24).

CREATE TABLE topology_nodes (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    site_id         UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL CHECK (kind IN
                    ('asset','interface','network','vlan','router','switch','access_point','gateway','scanner','sensor')),
    ref_id          TEXT NOT NULL,
    label           TEXT NOT NULL DEFAULT '',
    props           JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (site_id, kind, ref_id)
);
CREATE INDEX idx_topo_nodes_site ON topology_nodes(site_id);

CREATE TABLE topology_edges (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    site_id         UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    src_node_id     UUID NOT NULL REFERENCES topology_nodes(id) ON DELETE CASCADE,
    dst_node_id     UUID NOT NULL REFERENCES topology_nodes(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL CHECK (kind IN
                    ('connected_to','routes_to','attached_to','neighbor_of','observed_through','communicates_with')),
    confidence      REAL NOT NULL DEFAULT 0.5,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (src_node_id, dst_node_id, kind)
);
CREATE INDEX idx_topo_edges_site ON topology_edges(site_id);
CREATE INDEX idx_topo_edges_src  ON topology_edges(src_node_id);
CREATE INDEX idx_topo_edges_dst  ON topology_edges(dst_node_id);

CREATE TABLE topology_evidence (
    id          UUID PRIMARY KEY,
    edge_id     UUID NOT NULL REFERENCES topology_edges(id) ON DELETE CASCADE,
    source      TEXT NOT NULL,
    statement   TEXT NOT NULL,
    detail      JSONB,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_topo_evidence_edge ON topology_evidence(edge_id);
