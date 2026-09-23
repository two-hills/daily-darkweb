# Roadmap

**Current status (2026-09-23):** Phase 1 + 2 core collectors done. Fixed a second real
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
- [ ] HIBP domain-search collector — **deferred**: requires owned+verified domains and
      an `HIBP_API_KEY`; revisit if the user ever has domains to protect
- [ ] LLM triage agent: summarize/rank alerts; wrapped data blocks; pydantic
      parse-or-reject with one bounded repair retry; prompt-injection tests
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
