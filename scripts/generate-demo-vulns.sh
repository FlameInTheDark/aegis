#!/usr/bin/env bash
# Bootstrap the vulnerability index without internet access using the
# synthetic fixtures in testdata/feeds (spec §105/§107).
set -euo pipefail
echo "Feeds normally run via the feed-worker. For offline demos:"
echo "  1. Start the stack:   docker compose -f deploy/compose/docker-compose.yml up -d"
echo "  2. Apply demo data:   psql \$AEGIS_DATABASE_URL -f scripts/seed/demo.sql"
echo "  3. Fixture-based tests cover parsing: go test ./internal/feeds/ ./internal/telemetry/"
echo "Fixtures: testdata/feeds/{kev_sample,epss_sample,nvd_sample,osv_sample}.json"
