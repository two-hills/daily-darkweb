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

## Email notifications (optional)

Off by default. To enable, on the machine that will run it:

1. Add SMTP credentials to `.env` (see `.env.example`) — for Gmail, use an
   [App Password](https://myaccount.google.com/apppasswords), never your real password.
2. Set `DAILY_DARKWEB_EMAIL=1` in the environment `ops/run_daily.sh` runs under — either
   `export DAILY_DARKWEB_EMAIL=1` before a manual run, or add an
   `<key>EnvironmentVariables</key>` dict with `DAILY_DARKWEB_EMAIL=1` to the launchd plist.
3. Test it once by hand: `DAILY_DARKWEB_EMAIL=1 bash ops/run_daily.sh` — check `.err.log`
   for `email: sent to ...` or a clear error if SMTP config is wrong.

Only sends when there are alerts or a collector failure (same trigger as the macOS
notification); clean runs stay silent. The email body has the full HTML report inline
plus the same file as an attachment. Delivery failure never affects the exit code or the
archived files — email is a convenience channel, not the source of truth.

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
