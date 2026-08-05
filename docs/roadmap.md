# Roadmap

**Current status (2026-07-27):** Phase 1 + 2 core collectors done. Found and fixed a real
gap: new CISA KEV entries with no watchlist-keyword match were being crowded out of a
shared top-10 landscape slot by ransomware volume (a live SharePoint RCE add was missed
this way). Fixed via `interface/digest_view.py`, which always shows every new KEV entry
in its own "Vulnerability watch" section; KEV items also now carry `due_date` (CISA's
remediation deadline) and CWE codes. Added a self-contained HTML digest
(`render_html.py`, `--format html` / `--html-out`) for actually reading the report,
with escaping tested against hostile scraped content. Scheduler recipe ready but
deliberately not activated — deployment target is the user's Mac mini. Email notifications added: `--email` CLI flag
sends the HTML digest (inline + attached) via SMTP when there are alerts/failures,
credentials from env/.env, off by default in ops/run_daily.sh (opt in via
`DAILY_DARKWEB_EMAIL=1`). 59 tests green.
Next: LLM triage agent, then paste/GitHub leak watch.

## Phase 1 — walking skeleton (DONE)
- [x] Pure core: models, watchlist matching, deterministic scoring, dedup — unit-tested
- [x] `ransomware_live` collector (fail-closed, timeout, transient-only retry, Retry-After)
- [x] Pipeline + markdown/JSON digest CLI with seen-state incremental runs
- [x] Tor collector legally gated in config; hostile-content and safe-yaml tests

## Phase 2 — breadth + AI triage
- [x] CISA KEV collector (confirmed exploited-in-the-wild vulns, 30-day window,
      keyword-scoped via watchlist; shared retry/fetch helper in collectors/base.py)
- [x] `due_date` + CWE on KEV items; dedicated "Vulnerability watch" digest section so
      unmatched CVEs are never crowded out by ransomware volume (digest_view.py)
- [x] HTML digest renderer (`render_html.py`) for browser reading — color-coded
      severity, clickable source links, escapes all scraped content
- [x] Email notifications (`email_send.py`, `--email` flag) — SMTP via env/.env,
      sends only on alerts/failures, redundant channel (never affects exit code)
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
