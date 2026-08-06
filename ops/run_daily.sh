#!/usr/bin/env bash
# Daily digest runner: archives output, maps exit codes to macOS notifications.
# Designed for launchd (see ops/com.dailydarkweb.digest.plist + docs/operations.md).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE_DIR="${DAILY_DARKWEB_ARCHIVE:-$REPO_DIR/digests}"
UV_BIN="${UV_BIN:-$(command -v uv || echo "$HOME/.local/bin/uv")}"

notify() {
    command -v osascript >/dev/null 2>&1 &&
        osascript -e "display notification \"$1\" with title \"Daily Darkweb\"" || true
}

# The pipeline owns 0/1/3, so a runner failure must never borrow one of them: launchd
# reads 1 as "alerts found", which would make a dead runner look like a normal alerting
# day. Anything that kills the script before the pipeline reports exits 4 instead.
RUNNER_ERROR=4
PIPELINE_RAN=0
on_exit() {
    local rc=$?
    if [ "$PIPELINE_RAN" -eq 0 ] && [ "$rc" -ne 0 ]; then
        notify "Runner error (exit $rc) - digest did NOT run. See ${ERR:-launchd logs}"
        exit "$RUNNER_ERROR"
    fi
}
trap on_exit EXIT

mkdir -p "$ARCHIVE_DIR"
STAMP="$(date +%Y-%m-%d)"
OUT="$ARCHIVE_DIR/$STAMP.md"
OUT_HTML="$ARCHIVE_DIR/$STAMP.html"
ERR="$ARCHIVE_DIR/$STAMP.err.log"

# Opt-in: set DAILY_DARKWEB_EMAIL=1 (env or launchd plist) once SMTP_* / EMAIL_TO are in
# .env. Off by default so this feature never starts sending mail on its own.
EMAIL_FLAG=()
if [ "${DAILY_DARKWEB_EMAIL:-0}" = "1" ]; then
    EMAIL_FLAG=(--email)
fi

cd "$REPO_DIR"
set +e
# ${A[@]+"${A[@]}"} not "${A[@]}": macOS ships bash 3.2, where expanding an empty
# array under `set -u` aborts the script as an unbound variable.
"$UV_BIN" run daily-darkweb --html-out "$OUT_HTML" ${EMAIL_FLAG[@]+"${EMAIL_FLAG[@]}"} >"$OUT" 2>"$ERR"
STATUS=$?
PIPELINE_RAN=1
set -e

case "$STATUS" in
    0) echo "clean run, no new alerts: $OUT_HTML" ;;
    1) notify "New alerts - open $OUT_HTML" ;;
    3) notify "Collector FAILURE - do not treat as all-clear. See $ERR" ;;
    *) notify "Unexpected error (exit $STATUS). See $ERR" ;;
esac
exit "$STATUS"
