# Roadmap

**Current status (2026-07-20):** Phase 1 complete; Phase 2 started — CISA KEV collector
live (verified: 24 recent exploited CVEs, keyword alerts firing at HIGH for
Cisco/Fortinet/AD). Awareness-mode pivot: user has no owned domains to watch, so the
watchlist is technology/sector/country interest filters and HIBP is deferred.
41 tests green. Scheduler recipe ready (ops/ + docs/operations.md) but deliberately
not activated — deployment target is the user's always-on Mac mini.
Next: LLM triage agent, then paste/GitHub leak watch.

## Phase 1 — walking skeleton (DONE)
- [x] Pure core: models, watchlist matching, deterministic scoring, dedup — unit-tested
- [x] `ransomware_live` collector (fail-closed, timeout, transient-only retry, Retry-After)
- [x] Pipeline + markdown/JSON digest CLI with seen-state incremental runs
- [x] Tor collector legally gated in config; hostile-content and safe-yaml tests

## Phase 2 — breadth + AI triage
- [x] CISA KEV collector (confirmed exploited-in-the-wild vulns, 30-day window,
      keyword-scoped via watchlist; shared retry/fetch helper in collectors/base.py)
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
