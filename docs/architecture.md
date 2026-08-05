# Architecture

## Intent

Continuous awareness of dark-web-originated threats (ransomware victim claims, breach
exposure, brand mentions, exploit chatter) **without** operating collectors on criminal
infrastructure. Researcher-run clearnet aggregators do the risky collection; we consume
their APIs, normalize, and reason deterministically.

## Layers (dependencies point inward)

```
interface (cli, digest_view, render_md/html, state file)  I/O allowed
    └── orchestration (pipeline)         async fan-out over collectors
            ├── collectors (adapters)    network I/O, per-call timeout, retry
            └── core (models, matching,  PURE: no I/O, no network, no AI,
                 scoring, dedup)         `now` always passed in
```

`interface/digest_view.py` is a format-agnostic view model shared by both renderers: it
splits observations by source so `cisa_kev` entries (a handful per week) always get their
own "Vulnerability watch" section instead of competing with `ransomware_live` volume
(dozens per day) for a shared top-N slot. `render.py` (markdown) and `render_html.py`
(self-contained static page, no server) both format the same `DigestView` — add a third
output format by writing one more renderer against it, not by touching the pipeline.

- Collectors implement the `Collector` protocol (`collect() -> CollectResult`) and
  normalize source records into `RawItem`. Adding a source never touches the core.
- `CollectResult.status == FAILED` is a first-class outcome ("could not determine").
  The pipeline surfaces it in the report; the CLI exits 3. Never a false all-clear.

## Scoring model (deterministic)

`score = source_base + Σ(distinct match-field weights) + recency_boost`, capped at 100;
unmatched signals are capped at 45 so background landscape never reaches alert grade.
Severity thresholds: ≥85 critical · ≥65 high · ≥45 medium · ≥25 low · else info.
Weights live in `core/scoring.py` as data — tune there, covered by tests.

## Threat model / guardrails

- **Untrusted input:** every scraped field is hostile data. It is matched/rendered as
  text, never executed or interpreted. YAML config via `safe_load` only.
- **Legal gate:** `tor_onion.enabled: true` fails config validation on purpose. Direct
  onion collection requires a sanctioned CTI program with documented legal approval,
  plus sandboxed egress and payload-avoidance design — none of which exist yet.
- **No payloads:** DLS/breach monitoring ingests metadata (who/when/sector/country),
  never stolen data itself.
- **Outbound safety:** collectors call only configured base URLs; per-call timeouts;
  retries on 429/5xx/timeouts only (honoring Retry-After, capped); auth/validation 4xx
  never retried; result sets bounded by `max_items`.
- **State:** `.state/seen.json` holds only dedup hashes, capped at 50k keys.
- **HTML output escapes everything.** `render_html.py` runs every scraped field through
  `html.escape` before interpolation — titles/bodies are untrusted and must never inject
  markup or script into a page that gets opened in a browser.
- **Email is a redundant channel, not a source of truth.** `interface/email_send.py`
  loads SMTP identity (user/recipient) from env/`.env` only — never hardcoded, and
  deliberately kept out of committed source since this repo is public. The password
  falls back to the macOS Keychain (`security find-generic-password`) when
  `SMTP_PASSWORD` is unset, reusing the same `claude-email-notify` item as
  `~/.claude/hooks/email-notify.py` instead of a second plaintext copy of the same
  secret — Keychain is itself a secret manager, consistent with the Safety baseline.
  Sends only when `should_notify()` is true (alerts or a collector failure). A send
  failure is logged to stderr and never changes the CLI's exit code — the archived
  `.md`/`.html` files remain authoritative either way.

## Collectors

| Source | Intel | Status |
|---|---|---|
| ransomware_live | ransomware DLS victim claims | live |
| cisa_kev | confirmed exploited-in-the-wild CVEs | live |
| Paste/GitHub leak watch | brand/asset mentions | planned |
| LLM triage agent | summarize/rank alerts (wrapped data, parse-or-reject) | planned |
| HaveIBeenPwned | breach exposure for owned domains | deferred (needs owned domains + key) |
| tor_onion | direct DLS mirrors | gated until legal approval |

**Awareness mode:** the watchlist needs no owned assets — keywords (technologies),
sectors, and countries act as interest filters that promote landscape signals to
alerts. Org/keyword matching is word-boundary based to avoid substring false hits.
