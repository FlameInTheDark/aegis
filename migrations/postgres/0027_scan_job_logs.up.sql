-- Job log persistence (v1.13.0): structured log lines emitted by scanning
-- jobs (network scans, SSH inventory). Scanners stream events over NATS;
-- the server persists them here and replays history to browser subscribers
-- before attaching them to the live WebSocket tail.
-- seq is a monotonic per-table cursor: the REST history endpoint pages with
-- "before <seq>" and the frontend de-dupes live events against it.
CREATE TABLE scan_job_logs (
    seq        BIGSERIAL PRIMARY KEY,
    scan_id    UUID NOT NULL,
    task_id    TEXT NOT NULL DEFAULT '',
    scanner_id TEXT NOT NULL DEFAULT '',
    org_id     UUID NOT NULL,
    ts         TIMESTAMPTZ NOT NULL,
    level      TEXT NOT NULL,
    source     TEXT NOT NULL,
    msg        TEXT NOT NULL,
    fields     JSONB
);

-- Detail view: "tail the log of scan X" — the hot path. DESC lets the
-- initial page fetch the NEWEST N lines with one index scan.
CREATE INDEX idx_joblogs_scan_seq ON scan_job_logs (scan_id, seq DESC);

-- Retention sweep (worker): purge everything older than the configured
-- window in one pass.
CREATE INDEX idx_joblogs_ts ON scan_job_logs (ts);
