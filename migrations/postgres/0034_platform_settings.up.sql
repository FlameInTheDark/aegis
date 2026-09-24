-- 0034 (v1.28.0): platform settings — a small key/value store for
-- operator-controlled behavior that has no dedicated table. Values are
-- JSONB so each key owns its documented shape; reads and writes go
-- through the settings API (settings:manage) and every change is audited.
--
-- Deliberately GLOBAL (no org scope): the keys it holds today govern the
-- shared analytics store (ClickHouse device_metrics retention), which is
-- a deployment-wide resource — per-tenant values could not be honored
-- independently on a single ClickHouse cluster.

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
