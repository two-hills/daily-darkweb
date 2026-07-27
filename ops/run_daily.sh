#!/usr/bin/env bash
# Daily digest runner: archives output, maps exit codes to macOS notifications.
# Designed for launchd (see ops/com.dailydarkweb.digest.plist + docs/operations.md).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE_DIR="${DAILY_DARKWEB_ARCHIVE:-$REPO_DIR/digests}"
UV_BIN="${UV_BIN:-$(command -v uv || echo "$HOME/.local/bin/uv")}"

mkdir -p "$ARCHIVE_DIR"
STAMP="$(date +%Y-%m-%d)"
OUT="$ARCHIVE_DIR/$STAMP.md"
OUT_HTML="$ARCHIVE_DIR/$STAMP.html"
ERR="$ARCHIVE_DIR/$STAMP.err.log"

cd "$REPO_DIR"
set +e
"$UV_BIN" run daily-darkweb --html-out "$OUT_HTML" >"$OUT" 2>"$ERR"
STATUS=$?
set -e

notify() {
    command -v osascript >/dev/null 2>&1 &&
        osascript -e "display notification \"$1\" with title \"Daily Darkweb\"" || true
}

case "$STATUS" in
    0) echo "clean run, no new alerts: $OUT_HTML" ;;
    1) notify "New alerts - open $OUT_HTML" ;;
    3) notify "Collector FAILURE - do not treat as all-clear. See $ERR" ;;
    *) notify "Unexpected error (exit $STATUS). See $ERR" ;;
esac
exit "$STATUS"
