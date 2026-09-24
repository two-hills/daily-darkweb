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
  matching/scoring; any LLM step only summarizes/classifies wrapped content. AI analyst
  notes are untrusted output too: schema-validated, link-free, escaped, labelled "AI
  generated", and they never feed matching, scoring or exit codes.
- **Fail closed.** A collector error returns an explicit FAILED result surfaced in the
  digest ("do not treat as all-clear"), never an empty success.

## Core workflow
`uv run daily-darkweb` → collectors (async, timeout, transient-only retry) → dedupe +
seen-state filter → watchlist match → deterministic score/severity → trends from state
history → markdown/JSON/HTML digest. AI notes are added afterwards by re-rendering a saved
report: `--report-out` then `--from-report … --notes notes.json` (no re-collection).
Exit codes: 0 clean · 1 alerts found · 3 collection failure · 4 runner died, no digest
(for schedulers).

## Repo layout
- `src/daily_darkweb/core/` — pure domain: models, matching, scoring, dedup, trends (no I/O/AI)
- `src/daily_darkweb/collectors/` — adapters returning normalized `RawItem`s
- `src/daily_darkweb/orchestration/pipeline.py` — collect → filter → score → report
- `src/daily_darkweb/interface/` — CLI + markdown render; owns state file `.state/seen.json`
- `config/watchlist.yaml` (your assets) · `config/sources.yaml` (collector toggles)
- `ops/routine_prompt.md` — the daily cloud Routine's instructions (paste into the Routine)
- Depth: `docs/architecture.md` · `docs/roadmap.md` (carries current status) ·
  `docs/operations.md` (Mac mini + cloud Routine runbooks)

## Definition of Done
`uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest -q`
all green, plus a real `uv run daily-darkweb` exercised end-to-end. New collectors ship
with mocked-HTTP tests including fail-closed cases; never hit live APIs in tests.

## Status
Phase 1 complete; Phase 2 underway — `cisa_kev` collector live; runs daily as a cloud
Routine with trends and AI analyst notes. **Awareness mode:** the user watches no owned
domains; watchlist = technology keywords + sectors + APJC countries. HIBP deferred
(needs owned domains). See docs/roadmap.md.
