# Roadmap

**Current status (2026-10-10):** Diagnostics now go to stderr. structlog was never
configured, and its default writes to stdout — the digest's own stream — so a failing
collector's warning opened the digest: `--format json` stopped parsing, `ops/run_daily.sh`
archived it inside the `.md`, and the Routine prompt had to tell the model to skip it.
`cli.main()` now routes structlog to stderr (UTC timestamps, colours only on a
terminal), with a regression test that fails without the fix. Routine prompt v8 drops the
workaround. 225 tests green. Next: LLM alert ranking.

**Previous status (2026-10-09):** New **`vulncheck_kev` collector** — the early-warning
layer: exploited CVEs that VulnCheck KEV lists but CISA KEV doesn't (yet), ~4 a day (116
in the last 30 days). Watchlist matches become full alerts (on live data: CVE-2024-49766,
werkzeug, flagged for ransomware use and not in CISA KEV); the rest are one line each
under Vulnerability watch, so a 7-day first-run backfill stays readable. When both
catalogues carry a CVE in the same run (sync lag), CISA's entry wins — it has the
federal deadline. Bearer token via the environment's API credentials (cloud) or
`VULNCHECK_API_TOKEN` (local); newest first via `sort=date_added`, at most six pages.
Trend line for VulnCheck-only additions (tracked per source, like HIBP). Routine prompt
v7: the AI notes call out early warnings. 224 tests green. Phase 2 sources are complete.

**Previous status (2026-10-08):** New **`hibp` collector**: Have I Been Pwned's public
breach catalogue (no key, CC BY 4.0, credited). Every breach newly loaded into HIBP shows
in a new **Breach watch** section — who, when, how many accounts, which data classes,
HIBP's own summary — and a daily count feeds the Trends ("Breaches added to HIBP", compared
only once its own history spans both weeks). HIBP's description is a display-only
`summary`: 21 of the 30 newest say "breach", which would have made that watchlist keyword
alert on every entry. The country is inferred from the site's country-code domain (generic
ccTLDs skipped, labelled as inferred), so APJC breaches alert — on the live catalogue,
Angel One (India, 6.8M accounts) did. Spam lists, fabricated and retired entries are
dropped; sensitive ones labelled. First run backfills 30 days (7 breaches), which makes
that day's report "heavy" and exercises the overview email layout. Routine prompt v6
reads the new section and is generic enough for upcoming sources. 201 tests green. Next:
VulnCheck KEV (free community token, already in the environment's API credentials).

**Previous status (2026-10-07):** ransomware.live moved to its **API PRO** (free key; the
keyless v2 API is personal-use only). The key lives in the cloud environment's API
credentials — the network proxy adds it, so it never enters the Routine's session; local
runs use `RANSOMWARE_LIVE_API_KEY`. Seen-state carries over: PRO permalinks drop the base64
padding that v2-era dedup keys kept, and the collector restores it (verified against the
live feeds: 87 overlapping victims, identical keys). PRO lists victims by discovery time,
which surfaced 11 claims (posted with older attack dates) that v2's recent list never
showed. New in the digest: per-group **exploited CVEs** (highest CVSS first), victim count
and latest claim; per-victim **infostealer exposure** counts and press-coverage links.
Fields that point at leak sites or our account (`post_url`, `screenshot`, `locations`,
`client`) are never read. Heavy reports (> 25 KB) now get a deterministic **overview** as
the email body with the full report attached (`--overview-out`, prompt v5). Next: HIBP
breach catalogue (no key), then VulnCheck KEV (free community token).

**Previous status (2026-09-29):** The digest now reads on its own — the project's purpose
is that nobody on our side has to visit the dark web or leak-site mirrors. Alerts carry
victim context, the unverified claim text and KEV details inline; a new **Threat actor
profiles** section (ransomware.live structured group data: description, first seen,
aliases, ATT&CK initial-access techniques with details, defence-relevant tactics, tools)
covers the groups behind alerts and the most active ones, and the AI notes use it for
concrete defensive actions. `core/sanitize.py` scrubs .onion addresses, URLs and emails
from all scraped text at the collector boundary; leak-site fields (`claim_url`,
`screenshot`, group `locations`) are never read; source markup is flattened. Links stay
as labelled backups. Ops: two Routine runs had stranded their state on the session's own
`claude/*` branch (items would repeat) — `main` was fast-forwarded and the Routine now
uses `ops/persist_state.sh`, which pushes to `main` explicitly and fails loudly. 149 tests
green. Next: structlog to stderr, then LLM alert ranking; optional NVD/CVSS enrichment
for KEV items (needs `services.nvd.nist.gov` allowlisted).

**Previous status (2026-09-24):** Running daily as a claude.ai cloud Routine (prompt in
`ops/routine_prompt.md`; setup lessons in docs/operations.md): the environment needed
`api.ransomware.live` + `www.cisa.gov` allowlisted, the Claude GitHub App for the state
push, and the Gmail connector for HTML email because SMTP cannot egress from the cloud.
New: per-day `history` in the state file and a deterministic Trends section
(`core/trends.py`: week-over-week once 14 days exist, new groups, watchlist-country
share, KEV deadlines in the next 7 days), plus **AI analyst notes** — the Routine's
model writes `notes.json` from the finished digest; the CLI validates it (strict schema,
no links), and renders it escaped and labelled "AI generated" via
`--report-out` / `--from-report` / `--notes`. ransomware.live's own `[AI generated]`
descriptions get a badge. Watchlist now covers Check Point, breach terms, and APJC.
123 tests green. Next: structlog to stderr (log lines currently pollute stdout on
collector failure), then LLM alert ranking.

**Previous status (2026-09-23):** Phase 1 + 2 core collectors done. Fixed a second real
KEV coverage gap: the collector filtered on a fixed `recent_days: 30` window anchored to
"now", so a pipeline idle longer than that (last run 2026-08-18 → next 2026-09-23)
silently never reported entries added in between (verified misses: CVE-2026-73570
Zimbra, CVE-2026-72530/72529 TrueConf, CVE-2026-64849 MLflow — all recovered after the
fix). `.state/seen.json` now records `last_success` (advanced only by failure-free
runs); the CLI computes the effective window as `max(recent_days, gap)` capped at 365d
and passes an explicit `since` date to the collector, which no longer reads the wall
clock — deterministic and testable. `max_items` truncation now keeps the *newest*
entries. 80 tests green. Earlier milestone, kept for context: new KEV entries with no
watchlist-keyword match were being crowded out of a shared top-10 landscape slot by
ransomware volume (a live SharePoint RCE add was missed
this way). Fixed via `interface/digest_view.py`, which always shows every new KEV entry
in its own "Vulnerability watch" section; KEV items also now carry `due_date` (CISA's
remediation deadline) and CWE codes. Added a self-contained HTML digest
(`render_html.py`, `--format html` / `--html-out`) for actually reading the report,
with escaping tested against hostile scraped content. Scheduler recipe ready but
deliberately not activated — deployment target is the user's Mac mini. Email
notifications added: `--email` CLI flag sends the HTML digest (inline + attached) via
SMTP when there are alerts/failures. Password sources from the macOS Keychain
(`claude-email-notify`, shared with `~/.claude/hooks/email-notify.py`) so the same
Gmail App Password isn't duplicated into `.env`; identity (user/recipient) stays in
`.env` only, never hardcoded. Off by default in ops/run_daily.sh (opt in via
`DAILY_DARKWEB_EMAIL=1`).
Next: LLM triage agent, then paste/GitHub leak watch.

## Phase 1 — walking skeleton (DONE)
- [x] Pure core: models, watchlist matching, deterministic scoring, dedup — unit-tested
- [x] `ransomware_live` collector (fail-closed, timeout, transient-only retry, Retry-After)
- [x] Pipeline + markdown/JSON digest CLI with seen-state incremental runs
- [x] Tor collector legally gated in config; hostile-content and safe-yaml tests

## Phase 2 — breadth + AI triage
- [x] CISA KEV collector (confirmed exploited-in-the-wild vulns, 30-day minimum window,
      keyword-scoped via watchlist; shared retry/fetch helper in collectors/base.py)
- [x] `due_date` + CWE on KEV items; dedicated "Vulnerability watch" digest section so
      unmatched CVEs are never crowded out by ransomware volume (digest_view.py)
- [x] Gap-aware KEV lookback: state file records `last_success` (only failure-free runs
      advance it); CLI widens the window to cover the gap since then (365d cap) and
      injects an explicit `since` date, keeping the collector wall-clock-free
- [x] HTML digest renderer (`render_html.py`) for browser reading — color-coded
      severity, clickable source links, escapes all scraped content
- [x] Email notifications (`email_send.py`, `--email` flag) — SMTP identity via
      env/.env, password via macOS Keychain fallback (shared with the Claude Code
      notify hook); sends only on alerts/failures, redundant channel (never affects
      exit code)
- [x] HIBP breach-catalogue collector (`hibp`): public `/breaches`, no key; Breach watch
      section, display-only summaries, ccTLD country inference, breach trend
- [ ] HIBP domain-search collector — **deferred**: requires owned+verified domains and
      an `HIBP_API_KEY`; revisit if the user ever has domains to protect
- [x] VulnCheck KEV collector (`vulncheck_kev`) — exploited CVEs not yet in CISA KEV
      (free community token); CISA wins overlaps; compact list + alerts on matches
- [x] Daily history + Trends section (`core/trends.py`, state `history` capped at 60
      days; comparisons only once history spans both windows)
- [x] AI analyst notes (summarize half of LLM triage): produced by the cloud Routine's
      model from the finished digest; `AnalystNotes` parse-or-reject (bounded, no
      links), one repair retry in the Routine prompt, escaped + labelled "AI generated",
      fail-soft ("unavailable"), never feeds scoring or exit codes
- [ ] LLM triage agent, rank half: re-rank alerts; wrapped data blocks; prompt-injection
      tests
- [ ] Semaphore-bounded collector concurrency + per-source rate limits

## Phase 3 — operations
- [x] Scheduler recipe: ops/run_daily.sh + launchd plist template + docs/operations.md
      runbook (digest archive, notify on exit 1/3). **Activation deferred by choice** —
      will be deployed on the user's always-on Mac mini, not the dev MacBook.
- [ ] Paste-site / GitHub leak watch collector (brand & asset mentions)
- [ ] Digest sinks: file archive, optional webhook/email
- [ ] CI: ruff + mypy + pytest on PR; pip-audit dependency scan

## Phase 4 — gated expansion (requires legal sign-off)
- [ ] Written scope & legal approval for direct onion mirrors of ransomware DLS
- [ ] Sandboxed Tor egress design; payload-avoidance and content-safety controls
- [ ] Only then: implement `tor_onion` collector behind the existing config gate
