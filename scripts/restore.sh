#!/usr/bin/env bash
# Restore PostgreSQL from a backup dir. Requires CONFIRM=yes.
set -euo pipefail
[[ "${CONFIRM:-}" == "yes" ]] || { echo "refusing to run without CONFIRM=yes"; exit 1; }
DIR="${1:?usage: restore.sh backups/<stamp>}"
PG_URL="${AEGIS_DATABASE_URL:?set AEGIS_DATABASE_URL}"
echo "[restore] applying $DIR/postgres.sql"
psql "$PG_URL" < "$DIR/postgres.sql"
echo "[restore] done. Redis/NATS are non-authoritative and need no restore (§157)."
