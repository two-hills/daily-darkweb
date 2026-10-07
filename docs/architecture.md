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
                 scoring, dedup, trends, `now` always passed in
                 sanitize)
```

`interface/digest_view.py` is a format-agnostic view model shared by both renderers: it
splits observations by source so `cisa_kev` entries (a handful per week) always get their
own "Vulnerability watch" section and `hibp` entries their own "Breach watch", instead of
competing with `ransomware_live` volume (dozens per day) for a shared top-N slot. `render.py` (markdown) and `render_html.py`
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
- **API keys never enter the cloud session.** ransomware.live's API PRO wants an
  `X-API-KEY` header and VulnCheck an `Authorization: Bearer` token. In the cloud Routine
  the environment's API credentials make the network proxy add each one to requests for
  its host (`api-pro.ransomware.live`, `api.vulncheck.com`) after they leave the session,
  so neither the model nor any command ever sees them (a prompt-injected digest has
  nothing to exfiltrate). Local runs read `RANSOMWARE_LIVE_API_KEY` / `VULNCHECK_API_TOKEN`
  from env/.env (`config.ApiKeys`, `SecretStr`s), and each travels as a per-request header
  to its own source only. A missing or rejected key is an explicit FAILED, never retried.
- **State:** `.state/seen.json` holds only dedup hashes (capped at 50k keys) plus
  `last_success`, the timestamp of the last run with zero collector failures. The CLI
  stretches the KEV, HIBP and VulnCheck lookback windows to
  `max(recent_days, days since last_success)`
  (capped at 365d), so a pipeline that sat idle — or failed — for longer than the
  configured window still reports everything added in between instead of silently
  skipping it. Failed runs never advance the timestamp. It also keeps `history`: one
  compact per-day summary (counts per group/sector/country, KEV additions with due
  dates, breaches added, VulnCheck-only exploited CVEs; 60 days) from which
  `core/trends.py` computes the digest's Trends section — week-over-week comparisons only
  once history spans both windows (14 days). The breach and VulnCheck counts are `None` on
  days their source wasn't read, so their comparisons wait until *their own* history spans
  both windows.
- **AI analyst notes are untrusted output, never logic.** An optional model (the cloud
  Routine's session) reads the finished digest and writes `notes.json`; the CLI re-renders
  a saved report with it (`--report-out` → `--from-report … --notes …`, no re-collection,
  state untouched). `AnalystNotes` is a strict schema (bounded sizes, extra keys
  forbidden) that **refuses links**, so injected scraped content can't turn the notes
  into a phishing vector. Notes are HTML-escaped, labelled "AI generated — may be
  wrong", and never feed matching, scoring or exit codes; a missing or rejected file
  renders as "unavailable" instead of blocking the digest. Source text a feed marks
  `[AI generated]` (ransomware.live descriptions) gets a visible badge too.
- **Readable without visiting any source.** The point of the pipeline is that nobody on
  our side opens leak sites or dark-web mirrors, so the digest carries the details
  inline: victim context, the (unverified) claim text, infostealer exposure counts and a
  press-coverage link when the source has them, KEV summary / required action / deadline,
  and a **threat-actor profile** per relevant group (description, first and latest claim,
  victim count, MITRE ATT&CK initial-access techniques with details, the CVEs the group
  exploits, the defence-relevant tactics, and tools) from ransomware.live's structured
  group data. Profiles are
  fetched after scoring for the groups behind watchlist alerts first, then the most
  active ones (`group_profiles`, default 5), one request at a time; a failed lookup is
  listed in the digest and is never a collection failure. Links remain only as backup
  references (clearnet https pages built from structured fields).
- **No leak-site links, ever.** `core/sanitize.py` scrubs every scraped text field at the
  collector boundary: .onion addresses, URLs with a scheme and email addresses become
  markers (bare domains stay — a victim's website identifies it). Source markup (`<BR>`,
  quote markers) is flattened to plain text. The feed's leak-site fields (`post_url`,
  formerly `claim_url`; `screenshot`; group `locations`) and its account field (`client`,
  the key owner's address) are never modelled, so they cannot reach state, reports or
  email. Direct dark-web access stays out of scope: deeper coverage comes from
  a sanctioned CTI provider's API as a new collector, not from routing around company or
  ISP controls.
- **Breach catalogue, not breach searches.** The `hibp` collector reads Have I Been
  Pwned's public catalogue (no key) and never looks up an email address or domain. It
  keeps metadata only (who, when, how many accounts, which data classes, HIBP's flags);
  spam lists, fabricated and retired entries are dropped, sensitive ones labelled. HIBP's
  own incident description becomes `RawItem.summary`, which is shown but never matched:
  nearly every description says "breach", which would otherwise make that watchlist
  keyword fire on every entry. HIBP has no country field, so the collector infers one from
  the site's country-code TLD (skipping generic-use ccTLDs such as .io or .gg) and the
  digest says it is inferred. Data is CC BY 4.0; the Breach watch section credits it.
- **VulnCheck KEV is the early-warning layer, CISA KEV the authority.** The
  `vulncheck_kev` collector emits only exploited CVEs CISA hasn't listed (≈4 a day), newest
  first from a 7-day floor (the API serves at most six pages per query). If both sources
  carry a CVE in the same run (catalogue sync lag), the pipeline keeps CISA's entry, which
  has the federal deadline. Watchlist matches become full alerts; the rest are one line
  each under Vulnerability watch, so the email stays short. Exploitation evidence is
  counted, not linked; the reference is the NVD page. VulnCheck asks for attribution: the
  section credits it.
- **HTML output escapes everything.** `render_html.py` runs every scraped field through
  `html.escape` before interpolation — titles/bodies are untrusted and must never inject
  markup or script into a page that gets opened in a browser.
- **The HTML is also the email body, so it must be email-safe.** Gmail and Outlook drop
  CSS custom properties; with `var()` colours the body lost its cards and badges (badge
  text went white-on-white) while the same file looked fine opened in a browser. Colours
  are literal values generated per palette (light, plus a dark `@media` block), badges
  carry inline colours too, and a test fails if `var(` ever reappears. Heavy reports get a
  deterministic, link-free **overview** (`render_html_overview`, `--overview-out`) as the
  email body — status, AI notes, one line per alert and exploited CVE, trends — with the
  full report attached, so the attachment never has to be dropped for size.
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
| ransomware_live | ransomware DLS victim claims, group intel (API PRO, free key) | live |
| cisa_kev | confirmed exploited-in-the-wild CVEs | live |
| Paste/GitHub leak watch | brand/asset mentions | planned |
| LLM triage agent | summarize/rank alerts (wrapped data, parse-or-reject) | notes live via cloud Routine; ranking planned |
| hibp | newly loaded breaches (public catalogue, no key) | live |
| HaveIBeenPwned domain search | breach exposure for owned domains | deferred (needs owned domains + key) |
| vulncheck_kev | exploited CVEs not (yet) in CISA KEV (free community token) | live |
| tor_onion | direct DLS mirrors | gated until legal approval |

**Awareness mode:** the watchlist needs no owned assets — keywords (technologies),
sectors, and countries act as interest filters that promote landscape signals to
alerts. Org/keyword matching is word-boundary based to avoid substring false hits.
