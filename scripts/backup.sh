#!/usr/bin/env bash
# Backup all stores (spec §157). Requires CONFIRM=yes to run.
set -euo pipefail
[[ "${CONFIRM:-}" == "yes" ]] || { echo "refusing to run without CONFIRM=yes"; exit 1; }
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="${1:-./backups/$STAMP}"
mkdir -p "$OUT"
PG_URL="${AEGIS_DATABASE_URL:?set AEGIS_DATABASE_URL}"
echo "[backup] postgres -> $OUT/postgres.sql"
pg_dump "$PG_URL" > "$OUT/postgres.sql"
if [[ -n "${AEGIS_CLICKHOUSE_URL:-}" ]]; then
  echo "[backup] clickhouse (schema+tables via clickhouse-backup if installed)"
  command -v clickhouse-backup >/dev/null && clickhouse-backup create "aegis-$STAMP" || echo "  (clickhouse-backup not installed; use BACKUP TABLE manually)"
fi
if [[ -n "${AEGIS_S3_ENDPOINT:-}" ]]; then
  echo "[backup] object storage mirror via mc (if configured)"
  command -v mc >/dev/null && mc mirror "${MC_ALIAS:-aegis}" "$OUT/objects" || echo "  (mc not configured; skip)"
fi
echo "[backup] done: $OUT"
