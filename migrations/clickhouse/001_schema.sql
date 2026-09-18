-- Aegis ClickHouse schema — high-volume security event analytics (spec §23).
-- MergeTree family, time partitioning, configurable TTL retention.

CREATE DATABASE IF NOT EXISTS aegis;

CREATE TABLE IF NOT EXISTS aegis.security_events
(
    event_id       UUID,
    tenant_id      UUID,
    site_id        UUID,
    sensor_id      LowCardinality(String) DEFAULT '',
    agent_id       UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    timestamp      DateTime64(3, 'UTC'),
    event_type     LowCardinality(String),
    source         LowCardinality(String),
    source_version LowCardinality(String) DEFAULT '',
    schema_version LowCardinality(String) DEFAULT '1',
    src_asset_id   UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    src_ip         IPv6,
    src_port       UInt16 DEFAULT 0,
    dst_asset_id   UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000'),
    dst_ip         IPv6,
    dst_port       UInt16 DEFAULT 0,
    protocol       LowCardinality(String) DEFAULT '',
    direction      LowCardinality(String) DEFAULT '',
    severity       LowCardinality(String) DEFAULT 'info',
    action         LowCardinality(String) DEFAULT '',
    rule_id        String DEFAULT '',
    rule_name      String DEFAULT '',
    application    LowCardinality(String) DEFAULT '',
    hostname       String DEFAULT '',
    user           String DEFAULT '',
    process        String DEFAULT '',
    payload_meta   String DEFAULT '' CODEC(ZSTD(3)),   -- JSON, bounded; large payloads go to object storage
    raw_reference  String DEFAULT '',
    tags           Array(String),
    INDEX idx_rule rule_name TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, tenant_id, site_id, event_type)
TTL toDateTime(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS aegis.network_connections
(
    event_id    UUID,
    tenant_id   UUID,
    site_id     UUID,
    timestamp   DateTime64(3, 'UTC'),
    src_ip      IPv6,
    src_port    UInt16,
    dst_ip      IPv6,
    dst_port    UInt16,
    protocol    LowCardinality(String),
    direction   LowCardinality(String),
    conn_state  LowCardinality(String) DEFAULT '',
    duration_ms UInt64 DEFAULT 0,
    orig_bytes  UInt64 DEFAULT 0,
    resp_bytes  UInt64 DEFAULT 0,
    orig_pkts   UInt64 DEFAULT 0,
    resp_pkts   UInt64 DEFAULT 0,
    application LowCardinality(String) DEFAULT '',
    service     LowCardinality(String) DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, tenant_id, dst_port, protocol)
TTL toDateTime(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS aegis.dns_events
(
    event_id    UUID,
    tenant_id   UUID,
    site_id     UUID,
    timestamp   DateTime64(3, 'UTC'),
    src_ip      IPv6,
    query       String,
    qtype       LowCardinality(String) DEFAULT '',
    rcode       LowCardinality(String) DEFAULT '',
    answers     Array(String),
    ttl         UInt32 DEFAULT 0,
    rd          UInt8 DEFAULT 0
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, tenant_id, query)
TTL toDateTime(timestamp) + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS aegis.http_events
(
    event_id      UUID,
    tenant_id     UUID,
    site_id       UUID,
    timestamp     DateTime64(3, 'UTC'),
    src_ip        IPv6,
    dst_ip        IPv6,
    dst_port      UInt16,
    host          String,
    method        LowCardinality(String) DEFAULT '',
    uri           String DEFAULT '',
    status_code   UInt16 DEFAULT 0,
    user_agent    String DEFAULT '',
    content_type  LowCardinality(String) DEFAULT '',
    request_bytes UInt64 DEFAULT 0,
    response_bytes UInt64 DEFAULT 0
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, tenant_id, host)
TTL toDateTime(timestamp) + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS aegis.tls_events
(
    event_id     UUID,
    tenant_id    UUID,
    site_id      UUID,
    timestamp    DateTime64(3, 'UTC'),
    src_ip       IPv6,
    dst_ip       IPv6,
    dst_port     UInt16,
    version      LowCardinality(String) DEFAULT '',
    cipher       LowCardinality(String) DEFAULT '',
    server_name  String DEFAULT '',
    subject      String DEFAULT '',
    issuer       String DEFAULT '',
    validation   LowCardinality(String) DEFAULT '',
    ja3          String DEFAULT '',
    curve        LowCardinality(String) DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, tenant_id, server_name)
TTL toDateTime(timestamp) + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS aegis.ids_alerts
(
    event_id     UUID,
    tenant_id    UUID,
    site_id      UUID,
    sensor_id    LowCardinality(String),
    timestamp    DateTime64(3, 'UTC'),
    engine       LowCardinality(String),   -- suricata|snort
    signature_id UInt32 DEFAULT 0,
    signature    String DEFAULT '',
    category     LowCardinality(String) DEFAULT '',
    severity     UInt8 DEFAULT 2,
    action       LowCardinality(String) DEFAULT '',
    src_ip       IPv6,
    src_port     UInt16 DEFAULT 0,
    dst_ip       IPv6,
    dst_port     UInt16 DEFAULT 0,
    protocol     LowCardinality(String) DEFAULT '',
    raw_ref      String DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, tenant_id, severity, engine)
TTL toDateTime(timestamp) + INTERVAL 180 DAY;

CREATE TABLE IF NOT EXISTS aegis.flow_metrics
(
    tenant_id  UUID,
    site_id    UUID,
    bucket     DateTime,
    src_ip     IPv6,
    dst_ip     IPv6,
    dst_port   UInt16,
    protocol   LowCardinality(String),
    bytes_sum  UInt64,
    pkts_sum   UInt64,
    conns      UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(bucket)
ORDER BY (bucket, tenant_id, site_id, dst_port, protocol)
TTL toDateTime(bucket) + INTERVAL 365 DAY;

CREATE TABLE IF NOT EXISTS aegis.endpoint_events
(
    event_id    UUID,
    tenant_id   UUID,
    site_id     UUID,
    agent_id    UUID,
    timestamp   DateTime64(3, 'UTC'),
    type        LowCardinality(String),
    severity    LowCardinality(String) DEFAULT 'info',
    process     String DEFAULT '',
    user        String DEFAULT '',
    detail      String DEFAULT '' CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, tenant_id, agent_id, type)
TTL toDateTime(timestamp) + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS aegis.detection_matches
(
    match_id    UUID,
    tenant_id   UUID,
    site_id     UUID,
    rule_id     UUID,
    rule_type   LowCardinality(String),
    level       LowCardinality(String),
    entity      String DEFAULT '',
    timestamp   DateTime64(3, 'UTC'),
    summary     String,
    count       UInt64 DEFAULT 1
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, tenant_id, rule_id)
TTL toDateTime(timestamp) + INTERVAL 180 DAY;
