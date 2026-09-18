-- 0003: asset inventory — assets, identifiers, interfaces, addresses,
-- services, software (spec §9, §25).

CREATE TABLE assets (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    site_id         UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    hostname        TEXT NOT NULL DEFAULT '',
    fqdn            TEXT NOT NULL DEFAULT '',
    vendor          TEXT NOT NULL DEFAULT '',
    model           TEXT NOT NULL DEFAULT '',
    serial_number   TEXT NOT NULL DEFAULT '',
    device_type     TEXT NOT NULL DEFAULT 'unknown',
    os_family       TEXT NOT NULL DEFAULT '',
    os_name         TEXT NOT NULL DEFAULT '',
    os_version      TEXT NOT NULL DEFAULT '',
    kernel_version  TEXT NOT NULL DEFAULT '',
    architecture    TEXT NOT NULL DEFAULT '',
    os_confidence   REAL NOT NULL DEFAULT 0,
    os_sources      TEXT[] NOT NULL DEFAULT '{}',
    device_type_confidence REAL NOT NULL DEFAULT 0,
    device_type_sources TEXT[] NOT NULL DEFAULT '{}',
    exposure        TEXT NOT NULL DEFAULT 'unknown'
                    CHECK (exposure IN ('internal_only','vpn_only','publicly_reachable','unknown')),
    criticality     TEXT NOT NULL DEFAULT 'medium'
                    CHECK (criticality IN ('low','medium','high','critical')),
    risk_score      REAL NOT NULL DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_explanation TEXT NOT NULL DEFAULT '',
    has_agent       BOOLEAN NOT NULL DEFAULT false,
    agent_id        UUID,
    tags            TEXT[] NOT NULL DEFAULT '{}',
    owner           TEXT NOT NULL DEFAULT '',
    notes           TEXT NOT NULL DEFAULT '',
    demo_source     BOOLEAN NOT NULL DEFAULT false,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_assets_site        ON assets(site_id);
CREATE INDEX idx_assets_last_seen   ON assets(last_seen DESC);
CREATE INDEX idx_assets_device_type ON assets(device_type);
CREATE INDEX idx_assets_risk        ON assets(risk_score DESC);
CREATE INDEX idx_assets_org         ON assets(organization_id);
CREATE INDEX idx_assets_hostname    ON assets(hostname);
CREATE INDEX idx_assets_tags        ON assets USING gin(tags);

CREATE TABLE asset_identifiers (
    id         UUID PRIMARY KEY,
    asset_id   UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    type       TEXT NOT NULL,  -- agent_id|certificate|mac|serial|machine_id|cloud_instance|hostname|fqdn|ssh_hostkey|smb_name|ip
    value      TEXT NOT NULL,
    weight     REAL NOT NULL DEFAULT 0.5,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_asset_ident_type_value ON asset_identifiers(type, value);
CREATE INDEX idx_asset_ident_asset      ON asset_identifiers(asset_id);

CREATE TABLE network_interfaces (
    id         UUID PRIMARY KEY,
    asset_id   UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    mac        TEXT NOT NULL DEFAULT '',
    name       TEXT NOT NULL DEFAULT '',
    vlan_id    INTEGER,
    mtu        INTEGER,
    speed_mbps INTEGER,
    status     TEXT NOT NULL DEFAULT 'unknown',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_ifaces_asset ON network_interfaces(asset_id);
CREATE INDEX idx_ifaces_mac   ON network_interfaces(mac);

CREATE TABLE ip_addresses (
    id          UUID PRIMARY KEY,
    interface_id UUID NOT NULL REFERENCES network_interfaces(id) ON DELETE CASCADE,
    ip          INET NOT NULL,
    is_primary  BOOLEAN NOT NULL DEFAULT false,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_ips_iface ON ip_addresses(interface_id);
CREATE INDEX idx_ips_ip    ON ip_addresses(ip);

CREATE TABLE mac_addresses (
    id          UUID PRIMARY KEY,
    asset_id    UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    mac         TEXT NOT NULL,
    vendor      TEXT NOT NULL DEFAULT '',
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (asset_id, mac)
);

CREATE TABLE services (
    id               UUID PRIMARY KEY,
    asset_id         UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    organization_id  UUID NOT NULL,
    protocol         TEXT NOT NULL CHECK (protocol IN ('tcp','udp')),
    port             INTEGER NOT NULL CHECK (port > 0 AND port <= 65535),
    service_name     TEXT NOT NULL DEFAULT '',
    product          TEXT NOT NULL DEFAULT '',
    vendor           TEXT NOT NULL DEFAULT '',
    detected_version TEXT NOT NULL DEFAULT '',
    version_range    TEXT NOT NULL DEFAULT '',
    version_confidence REAL NOT NULL DEFAULT 0,
    cpes             TEXT[] NOT NULL DEFAULT '{}',
    banner           TEXT NOT NULL DEFAULT '',
    tls              JSONB,
    http             JSONB,
    sources          TEXT[] NOT NULL DEFAULT '{}',
    confidence       REAL NOT NULL DEFAULT 0.5,
    exposure         TEXT NOT NULL DEFAULT 'unknown'
                     CHECK (exposure IN ('internal_only','vpn_only','publicly_reachable','unknown')),
    flags            TEXT[] NOT NULL DEFAULT '{}',
    state            TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open','closed','filtered')),
    first_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (asset_id, protocol, port)
);
CREATE INDEX idx_services_asset_port ON services(asset_id, protocol, port);
CREATE INDEX idx_services_product    ON services(product);
CREATE INDEX idx_services_version    ON services(detected_version);
CREATE INDEX idx_services_org        ON services(organization_id);
CREATE INDEX idx_services_port       ON services(port);

CREATE TABLE service_observations (
    id          UUID PRIMARY KEY,
    service_id  UUID NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    scan_id     UUID,
    source      TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    raw         JSONB,
    confidence  REAL NOT NULL DEFAULT 0.5
);
CREATE INDEX idx_service_obs_service ON service_observations(service_id, observed_at DESC);

CREATE TABLE software (
    id          UUID PRIMARY KEY,
    asset_id    UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL DEFAULT '',
    vendor      TEXT NOT NULL DEFAULT '',
    ecosystem   TEXT NOT NULL DEFAULT '',
    purl        TEXT NOT NULL DEFAULT '',
    cpes        TEXT[] NOT NULL DEFAULT '{}',
    source      TEXT NOT NULL DEFAULT '',
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (asset_id, name, version, ecosystem)
);
CREATE INDEX idx_software_asset ON software(asset_id);
CREATE INDEX idx_software_purl  ON software(purl) WHERE purl <> '';
CREATE INDEX idx_software_name  ON software(name);

CREATE TABLE software_observations (
    id          UUID PRIMARY KEY,
    software_id UUID NOT NULL REFERENCES software(id) ON DELETE CASCADE,
    agent_id    UUID,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    raw         JSONB
);
CREATE INDEX idx_software_obs ON software_observations(software_id, observed_at DESC);
