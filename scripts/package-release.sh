#!/usr/bin/env bash
# Package a clean source-tree release archive: exactly the git-tracked
# files of HEAD (plus .env.example, tracked). Packaging from the git index
# is deterministic — untracked dev artifacts (postgres test cluster,
# dockerfile-check binaries, tool-results, downloads) and local secrets
# (.env is not tracked) can never leak into a release.
set -euo pipefail
ROOT=/home/z/my-project
VER=$(cat "$ROOT/VERSION")
OUT=$ROOT/download
STAGE=/tmp/aegis-pkg-$VER

rm -rf "$STAGE"
mkdir -p "$STAGE/aegis"
cd "$ROOT"

# Export the tracked tree (respects .gitattributes export-ignore) into the
# staging dir, then wrap it with the standard aegis/ top-level folder.
git -C "$ROOT" archive --format=tar HEAD | tar -xf - -C "$STAGE/aegis"
# VERSION file already tracked; keep a copy of the packaging manifest.
git -C "$ROOT" log -1 --format=%H > "$STAGE/aegis/RELEASE_COMMIT"

cd "$STAGE"
TARF=$OUT/aegis-v$VER.tar.gz
ZIPF=$OUT/aegis-v$VER.zip
rm -f "$TARF" "$ZIPF" "$OUT/aegis-v$VER.sha256"
tar -czf "$TARF" aegis
cd aegis && zip -qr "$ZIPF" . && cd ..
sha256sum "$TARF" "$ZIPF" > "$OUT/aegis-v$VER.sha256"
rm -rf "$STAGE"
ls -la "$OUT" | grep "v$VER"
echo "PACKAGED v$VER (tracked files of $(git -C "$ROOT" log -1 --format=%h HEAD))"
