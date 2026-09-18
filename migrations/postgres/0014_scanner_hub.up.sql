-- 0014: gRPC scanner hub — remote scanners connect from physical hosts.
-- token_hash  : SHA-256 of the enrollment token issued via the API
-- transport   : 'grpc' (agent dialed the hub) | 'nats' (compose-embedded)
-- is_default  : org-level default scanner for scans without explicit choice
ALTER TABLE scanners ADD COLUMN IF NOT EXISTS token_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE scanners ADD COLUMN IF NOT EXISTS transport TEXT NOT NULL DEFAULT 'nats';
ALTER TABLE scanners ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT false;
