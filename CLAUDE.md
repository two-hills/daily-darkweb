# Daily Darkweb — clearnet-first CTI pipeline

Collects dark-web-derived threat intel from **safe clearnet aggregators**, matches it
against a watchlist, scores it deterministically, and emits a daily digest. Goal:
real-world threat awareness and early prevention for security professionals.

## Locked decisions
- **Clearnet-first.** No direct onion/Tor collection. The `tor_onion` source is a gated
  stub: enabling it in config raises an error until documented legal approval exists.
- **Metadata only.** Collectors ingest victim/indicator *metadata* — never leaked
  payloads, credentials, or stolen data.
- **Scraped content is untrusted data**, never instructions. Deterministic core does all
  matching/scoring; any future LLM step only summarizes/classifies wrapped content.
- **Fail closed.** A collector error returns an explicit FAILED result surfaced in the
  digest ("do not treat as all-clear"), never an empty success.

## Core workflow
`uv run daily-darkweb` → collectors (async, timeout, transient-only retry) → dedupe +
seen-state filter → watchlist match → deterministic score/severity → markdown/JSON digest.
Exit codes: 0 clean · 1 alerts found · 3 collection failure (for schedulers).

## Repo layout
- `src/daily_darkweb/core/` — pure domain: models, matching, scoring, dedup (no I/O/AI)
- `src/daily_darkweb/collectors/` — adapters returning normalized `RawItem`s
- `src/daily_darkweb/orchestration/pipeline.py` — collect → filter → score → report
- `src/daily_darkweb/interface/` — CLI + markdown render; owns state file `.state/seen.json`
- `config/watchlist.yaml` (your assets) · `config/sources.yaml` (collector toggles)
- Depth: `docs/architecture.md` · `docs/roadmap.md` (carries current status)

## Definition of Done
`uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest -q`
all green, plus a real `uv run daily-darkweb` exercised end-to-end. New collectors ship
with mocked-HTTP tests including fail-closed cases; never hit live APIs in tests.

## Status
Phase 1 complete; Phase 2 underway — `cisa_kev` collector live. **Awareness mode:** the
user watches no owned domains; watchlist = technology keywords + sectors + countries.
HIBP deferred (needs owned domains). See docs/roadmap.md.
