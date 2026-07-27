# Operations — daily run on a Mac mini

Deployment is prepared but **not activated on the dev MacBook** (it sleeps/turns off).
Target: an always-on Mac mini running the digest every morning via launchd.
launchd (not cron) because it fires missed jobs after sleep/reboot.

## One-time setup on the Mac mini

```sh
# 1. Install uv (if missing)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. Get the repo (git clone, or copy the project directory)
git clone <repo-or-copy> ~/Apps/Daily_Darkweb
cd ~/Apps/Daily_Darkweb
uv sync

# 3. Prove it works end-to-end once, by hand
bash ops/run_daily.sh
# expect: digests/YYYY-MM-DD.md and .html created; exit code 0/1/3
open digests/$(date +%Y-%m-%d).html   # read it in a browser

# 4. Install the launchd job (07:30 daily; edit Hour/Minute in the plist to taste)
sed -e "s|__REPO_DIR__|$HOME/Apps/Daily_Darkweb|g" -e "s|__HOME__|$HOME|g" \
    ops/com.dailydarkweb.digest.plist \
    > ~/Library/LaunchAgents/com.dailydarkweb.digest.plist
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/com.dailydarkweb.digest.plist

# 5. Verify it is loaded, and force one run now
launchctl list | grep dailydarkweb
launchctl kickstart -k "gui/$(id -u)/com.dailydarkweb.digest"
```

## Day-to-day

- Digests archive to `digests/YYYY-MM-DD.md` (plain text) and `.html` (open in a browser —
  color-coded severity, clickable source links); stderr to `digests/YYYY-MM-DD.err.log`.
- macOS notification fires only when there are new alerts (exit 1) or a collector
  failed (exit 3 — "do not treat as all-clear"). Clean runs (0) are silent.
- Runner/launchd logs: `~/Library/Logs/daily-darkweb.log` / `.err.log`.
- Seen-state lives in `.state/seen.json` (machine-local, gitignored). First run on a
  new machine backfills the KEV 30-day window — that is expected, not a bug.

## Change the schedule / uninstall

```sh
launchctl bootout "gui/$(id -u)/com.dailydarkweb.digest"    # unload
# edit ~/Library/LaunchAgents/com.dailydarkweb.digest.plist, then bootstrap again
```

## Troubleshooting

- `launchctl list` shows last exit code next to the label (0/1/3 as above).
- Digest missing → check `.err.log` files; a FAILED collector section inside the
  digest itself means the run worked but an upstream source did not.
- After moving the repo, regenerate the plist (step 4) — it embeds absolute paths.
