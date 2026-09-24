# 🌒 daily-darkweb

A clearnet-first threat intelligence digest for security professionals who want to stay
current on real-world dark-web-derived activity — ransomware victim claims and vulnerabilities
confirmed exploited in the wild — without operating collectors on dark-web infrastructure. 🕵️

Run it daily and get a briefing — markdown, or a clean HTML email: what's new, what matches
your interests, how this week compares with last week, and what requires attention today. ☕📰

## 🔒 Why "clearnet-first"

Direct Tor/onion scraping carries legal and OPSEC risk even for defenders. Instead, this
project consumes **clearnet aggregators** — researchers who already monitor onion sites and
republish victim/indicator *metadata* over clean HTTPS APIs. You get broad coverage (currently
~200 ransomware groups' leak sites via one source) without touching onion infrastructure
yourself. Direct onion collection stays a gated stub (`tor_onion` in config) that refuses to
enable until documented legal approval exists — see [docs/architecture.md](docs/architecture.md).

## ⚙️ What it does

```
collectors (async, timeout, fail-closed)
    -> dedupe + seen-state filter (only new signals)
    -> watchlist match (keywords / orgs / domains / sectors / countries)
    -> deterministic scoring (source + match weights + recency -> severity)
    -> trends from daily history (this week vs last week, KEV deadlines)
    -> markdown / JSON / HTML digest
    -> optional AI analyst notes, added by re-rendering (labelled "AI generated")
```

- 🚫 **Fail-closed.** A collector error is surfaced in the digest as an explicit failure
  ("do not treat as all-clear") — never silently dropped or reported as a clean run.
- 🎯 **Deterministic.** No AI in the matching or scoring path. Same input always produces the
  same score; scraped content is matched as data, never interpreted as instructions.
- 📈 **Trends.** Each run adds a compact daily summary to the state file. The digest shows
  active groups, new groups, hit sectors and countries, your watchlist-country share, and
  KEV deadlines in the next 7 days — with week-over-week changes once 14 days of history
  exist (never compared against missing data).
- 🤖 **AI analyst notes (optional).** An LLM can add a short summary — trends, recommended
  actions, caveats — on top of the digest. The notes are untrusted output: schema-checked,
  size-limited, **links refused**, HTML-escaped, clearly labelled "AI generated — may be
  wrong", and they never change scores or exit codes. Source text that a feed itself marks
  as AI-written (ransomware.live descriptions) gets a visible badge too.
- 🛡️ **Metadata only.** Never ingests leaked payloads, credentials, or stolen data.

## 📡 Sources

| Source | Signal | Auth |
|---|---|---|
| [ransomware.live](https://ransomware.live) 💀 | Ransomware group victim-claim metadata | none |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) 🚨 | Vulnerabilities confirmed exploited in the wild | none |

Both are free and require no API key. See [docs/roadmap.md](docs/roadmap.md) for planned
sources (breach exposure, leak-site/paste watch, LLM alert ranking). 🗺️

## 🚀 Quickstart

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12+.

```sh
git clone <this-repo>
cd daily-darkweb
uv sync
uv run daily-darkweb --html-out digest.html && open digest.html   # 🌐 browsable report
```

Exit codes (scheduler-friendly): `0` ✅ clean · `1` ⚠️ alerts found · `3` ❌ collection failure.

Tune what counts as "your interests" in [config/watchlist.yaml](config/watchlist.yaml) —
technology keywords (e.g. Cisco, Fortinet, Check Point, breach terms), sectors, and
countries (APJC by default). No owned domains are required; the project ships in awareness
mode. Collector toggles live in [config/sources.yaml](config/sources.yaml).

### 🤖 Adding AI analyst notes

Collect once, let a model (or you) write notes from the digest, then re-render — the
re-render never collects again or touches the state file:

```sh
uv run daily-darkweb --report-out digests/report.json            # collect + save the run
# write digests/notes.json from the digest (see below)
uv run daily-darkweb --from-report digests/report.json \
    --notes digests/notes.json --html-out digests/digest.html     # digest with notes
```

`notes.json` must follow this shape — anything else (or any link) is rejected, and the
digest then says the notes are unavailable instead of failing:

```json
{
  "headline": "One sentence, max 200 characters",
  "points": ["1 to 6 key trends or changes"],
  "actions": ["0 to 5 recommendations"],
  "caveats": ["0 to 3 data gaps"]
}
```

## 📋 Sample output

```
## AI analyst notes (AI generated)
_AI generated from this digest by a language model — may be wrong; verify against the sourced items below before acting._

**Edge-device exploitation is accelerating; APJC manufacturing is a repeat target**
- CISA KEV additions rose to 9 this week (prev 4), mostly gateway and VPN products.
- Qilin was the most active group and hit two Japanese manufacturers.

Recommended actions:
- Patch internet-facing gateways first; two KEV deadlines fall in the next 7 days.

## Trends (last 7 days)
- Ransomware claims: 142 (prev 120, +18%)
- Most active groups: qilin 25 (prev 15, +67%), akira 18 (prev 20, -10%)
- Watchlist countries: 12 (prev 8, +50%) — JP 4 (prev 1, +300%), IN 3 (prev 2, +50%)
- CISA KEV additions: 9 (prev 4, +125%)
- KEV deadlines in the next 7 days: CVE-2026-93616 (due 2026-09-25), CVE-2026-85102 (due 2026-09-25)

## Watchlist alerts (3)
### [HIGH 73] CVE-2026-25089: Fortinet FortiSandbox OS Command Injection Vulnerability
- Matched: keyword=fortinet
- Source: `cisa_kev` | published: 2026-07-16
- Reference: https://nvd.nist.gov/vuln/detail/CVE-2026-25089
```

(Illustrative numbers. The HTML version is color-coded, with clickable source links.)

## ⏰ Running it daily

Two ways, both documented in [docs/operations.md](docs/operations.md):

- ☁️ **Cloud Routine on claude.ai** (no machine of your own): a scheduled Claude Code
  session runs the pipeline, commits the state file, writes the AI analyst notes, and emails
  the HTML digest (inline + attached) through the Gmail connector — every run, clean ones
  included, so a missing email always means something broke. The instructions to paste
  into the Routine are in [ops/routine_prompt.md](ops/routine_prompt.md); the setup
  (network allowlist, GitHub App, email) is in the
  [Cloud Routine runbook](docs/operations.md#cloud-routine-claudeai).
- 🖥️ **launchd on an always-on Mac:** archives digests locally and notifies only when
  there's something to see.

## 📧 Email notifications

- **Cloud Routine:** handled by the Routine through the Gmail connector (see above) —
  SMTP can't leave the cloud sandbox.
- **Local runs:** `--email` sends the HTML digest by SMTP (inline body + attachment) when
  there are alerts or a collector failure — silent on clean runs. Off by default; set
  `SMTP_USER` and `EMAIL_TO` in `.env` (see `.env.example`) to enable — the password can
  come from `SMTP_PASSWORD` or fall back to a macOS Keychain item, so it doesn't need to be
  duplicated anywhere.

Either way, email is a convenience channel — the digest itself stays authoritative.

## 🧪 Development

```sh
uv run ruff check . && uv run ruff format --check .   # lint + format
uv run mypy                                            # strict types
uv run pytest -q                                       # tests (mocked HTTP only, no live calls)
```

See [CLAUDE.md](CLAUDE.md) for locked project decisions and [docs/architecture.md](docs/architecture.md)
for the layered design and threat model.

## 📈 Status

Phase 1 and initial Phase 2 collectors complete and verified against live sources; running
daily as a cloud Routine with trends and AI analyst notes. See
[docs/roadmap.md](docs/roadmap.md) for current status and what's next.

## 📄 License

[MIT](LICENSE) — do good things with it. 🙂
