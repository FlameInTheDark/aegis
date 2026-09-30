#!/usr/bin/env bash
# package-archive.sh — build an incrementally numbered archive of the aegis
# tree into ../download/ (v1, v2, ... the number never regresses).
set -euo pipefail
cd "$(dirname "$0")/.."

NAME_PREFIX="aegis-improvement-plan"
OUT_DIR="../download"
mkdir -p "$OUT_DIR"

next=1
for f in "$OUT_DIR"/${NAME_PREFIX}-v*.zip; do
  [[ -e "$f" ]] || continue
  n=$(sed -E "s/.*-v([0-9]+)\.zip/\1/" <<< "$f")
  (( n >= next )) && next=$(( n + 1 ))
done

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
rsync -a --exclude '.git' --exclude 'node_modules' --exclude 'web/dist' \
  --exclude 'bin' ./ "$STAGE/${NAME_PREFIX}-v${next}/"

( cd "$STAGE" && zip -qr "$OLDPWD/$OUT_DIR/${NAME_PREFIX}-v${next}.zip" "${NAME_PREFIX}-v${next}" )
echo "created $OUT_DIR/${NAME_PREFIX}-v${next}.zip ($(stat -c%s "$OUT_DIR/${NAME_PREFIX}-v${next}.zip") bytes)"
