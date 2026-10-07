# 🌒 daily-darkweb

A clearnet-first threat intelligence digest for security professionals who want to stay
current on real-world dark-web-derived activity — ransomware victim claims, vulnerabilities
confirmed exploited in the wild, and newly published data breaches — without operating
collectors on dark-web infrastructure. 🕵️

Run it daily and get a briefing — markdown, or a clean HTML email: what's new, what matches
your interests, how this week compares with last week, and what requires attention today. ☕📰

## 🔒 Why "clearnet-first"

Direct Tor/onion scraping carries legal and OPSEC risk even for defenders. Instead, this
project consumes **clearnet aggregators** — researchers who already monitor onion sites and
republish victim/indicator *metadata* over clean HTTPS APIs. You get broad coverage (400+
ransomware groups' leak sites via one source) without touching onion infrastructure
yourself. Direct onion collection stays a gated stub (`tor_onion` in config) that refuses to
enable until documented legal approval exists — see [docs/architecture.md](docs/architecture.md).

## ⚙️ What it does

```
collectors (async, timeout, fail-closed)
    -> dedupe + seen-state filter (only new signals)
    -> watchlist match (keywords / orgs / domains / sectors / countries)
    -> deterministic scoring (source + match weights + recency -> severity)
    -> threat-actor profiles for the groups involved (TTPs, exploited CVEs, tools)
    -> trends from daily history (this week vs last week, KEV deadlines, new breaches)
    -> markdown / JSON / HTML digest
    -> optional AI analyst notes, added by re-rendering (labelled "AI generated")
```

- 📖 **Readable without visiting anything.** The whole point: nobody on your side needs
  to open leak sites or dark-web mirrors. Each alert carries its details inline — victim
  context, the (unverified) claim text, KEV summary, required action and deadline, what a
  breach exposed — and links remain only as a labelled backup.
- 🧭 **Threat actor profiles.** For the groups behind your alerts (then the most active
  ones), the digest explains who they are (first and latest claim, victim count), **how
  they get in** (MITRE ATT&CK initial-access techniques with details), **which
  vulnerabilities they exploit** (CVEs, highest CVSS first), how they operate (defence
  evasion, credential access, lateral movement, exfiltration, impact) and which tools they
  use — the input for a defence plan. Alerts also show the victim's infostealer exposure
  (counts of compromised employee/user credentials) and press coverage when known.
- ⏱️ **Early exploitation warnings.** VulnCheck KEV lists exploited CVEs days or weeks
  before CISA does. Those that match your watchlist (Cisco, Fortinet, VPN, ransomware use,
  …) become full alerts; the rest are one line each under Vulnerability watch, marked "not
  yet in CISA KEV". When CISA lists a CVE, its entry (with the federal deadline) wins.
- 🔓 **Breach watch.** Every breach newly loaded into Have I Been Pwned: who, when, how
  many accounts and which kinds of data, with HIBP's own summary. HIBP has no country
  field, so the digest infers one from the breached site's country-code domain (`.in`,
  `.co.jp`, …; labelled as inferred) — that is how an APJC breach reaches your alerts.
- 🧹 **No leak-site links, ever.** All scraped text is scrubbed of .onion addresses, URLs
  and email addresses before it's stored or shown; the source's leak-site, screenshot and
  account fields are never read.
- 🚫 **Fail-closed.** A collector error is surfaced in the digest as an explicit failure
  ("do not treat as all-clear") — never silently dropped or reported as a clean run.
- 🎯 **Deterministic.** No AI in the matching or scoring path. Same input always produces the
  same score; scraped content is matched as data, never interpreted as instructions.
- 📈 **Trends.** Each run adds a compact daily summary to the state file. The digest shows
  active groups, new groups, hit sectors and countries, your watchlist-country share, KEV
  deadlines in the next 7 days, breaches added and VulnCheck-only exploited CVEs — with
  week-over-week changes once 14 days of history exist (never compared against missing
  data).
- 🤖 **AI analyst notes (optional).** An LLM can add a short summary — trends, recommended
  actions, caveats — on top of the digest. The notes are untrusted output: schema-checked,
  size-limited, **links refused**, HTML-escaped, clearly labelled "AI generated — may be
  wrong", and they never change scores or exit codes. Source text that a feed itself marks
  as AI-written (ransomware.live descriptions) gets a visible badge too.
- 🛡️ **Metadata only.** Never ingests leaked payloads, credentials, or stolen data.

## 📡 Sources

| Source | Signal | Auth |
|---|---|---|
| [ransomware.live](https://ransomware.live) 💀 | Ransomware victim-claim metadata, group intel (TTPs, exploited CVEs, tools) | free API PRO key |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) 🚨 | Vulnerabilities confirmed exploited in the wild | none |
| [Have I Been Pwned](https://haveibeenpwned.com) 🔓 | Newly loaded data breaches (public catalogue, CC BY 4.0) | none |
| [VulnCheck KEV](https://vulncheck.com) ⏱️ | Exploited CVEs not (yet) in CISA KEV — early warning | free community token |

All are free. Two need a key: ransomware.live's API PRO
([ransomware.live/my](https://www.ransomware.live/my)) and VulnCheck's community API token
([vulncheck.com](https://vulncheck.com)). For local runs put `RANSOMWARE_LIVE_API_KEY` and
`VULNCHECK_API_TOKEN` in `.env`; the cloud Routine gets both from its environment's API
credentials instead — see [docs/operations.md](docs/operations.md). HIBP is read as a
catalogue only — the pipeline never looks up any email address or domain. See
[docs/roadmap.md](docs/roadmap.md) for planned work (leak-site/paste watch, LLM alert
ranking). 🗺️

## 🚀 Quickstart

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12+.

```sh
git clone <this-repo>
cd daily-darkweb
uv sync
echo 'RANSOMWARE_LIVE_API_KEY=<your free key>' >> .env            # 🔑 ransomware.live API PRO
echo 'VULNCHECK_API_TOKEN=<your free token>' >> .env              # 🔑 VulnCheck community
uv run daily-darkweb --html-out digest.html && open digest.html   # 🌐 browsable report
```

Exit codes (scheduler-friendly): `0` ✅ clean · `1` ⚠️ alerts found · `3` ❌ collection failure
· `4` 💥 the runner itself died, no digest (`ops/run_daily.sh`).

Tune what counts as "your interests" in [config/watchlist.yaml](config/watchlist.yaml) —
technology keywords (e.g. Cisco, Fortinet, Check Point, breach terms), sectors, and
countries (APJC by default). No owned domains are required; the project ships in awareness
mode. Collector toggles live in [config/sources.yaml](config/sources.yaml), including
`group_profiles` — how many threat-actor profiles each digest includes (default 5, 0 = off).

### 🤖 Adding AI analyst notes

Collect once, let a model (or you) write notes from the digest, then re-render — the
re-render never collects again or touches the state file:

```sh
uv run daily-darkweb --report-out digests/report.json            # collect + save the run
# write digests/notes.json from the digest (see below)
uv run daily-darkweb --from-report digests/report.json \
    --notes digests/notes.json --html-out digests/digest.html \
    --overview-out digests/overview.html                          # digest (+ email overview)
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
- Breaches added to HIBP: 4 (prev 6, -33%)
- Exploited CVEs added to VulnCheck KEV, not in CISA KEV: 27 (prev 31, -13%)

## Watchlist alerts (3)
### [HIGH 67] Example Diagnostics Ltd claimed by qilin
- Matched: sector=Healthcare, country=PH
- Source: `ransomware_live` | published: 2026-09-28 16:59 UTC
- Victim: Healthcare · PH · website example-diagnostics.test
- Description (unverified): Diagnostic laboratory; the group claims patient and billing data.
- Group: qilin — profile below
- Reference (backup link): https://www.ransomware.live/id/…

## Vulnerability watch (2)
Every new confirmed-exploited CVE from CISA KEV, beyond your watchlist.
No additional exploited CVEs outside your watchlist this run.

### Not yet in CISA KEV — reported exploited (VulnCheck KEV) (2)
Exploited CVEs that VulnCheck KEV lists but CISA KEV doesn't (yet), one line each; …
- [medium] CVE-2026-51886: Langflow Langflow Improper Control of Generation of Code ('Code Injection') — added 2026-10-06
- [medium] CVE-2026-95675: D-Link dap-1360_firmware OS Command Injection — added 2026-10-05

## Breach watch (1)
### [MEDIUM 45] Example Shop: 274,922 accounts exposed
- Source: `hibp` | published: 2026-10-07 05:42 UTC
- Exposed data: Email addresses, Names, Usernames
- Incident date: 2026-10-04 · added to Have I Been Pwned: 2026-10-07
- Summary: In October 2026, the online shop suffered a data breach attributed to …
- Reference (backup link): https://haveibeenpwned.com/Breach/…

## Threat actor profiles (1)
### qilin
_tracked since 2022-10-08; 2,342 victims claimed; latest claim 2026-10-07_
Qilin ransomware was first observed in July of 2022 … Qilin actors practice double extortion …
- How they get in (Initial Access):
  - Valid Accounts (T1078): Compromised credentials used to authenticate via VPN and RDP …
  - Exploit Public-Facing Application (T1190): Exploitation of vulnerabilities in VPN appliances …
- Vulnerabilities they exploit (highest CVSS first):
  - CVE-2025-31324 — SAP NetWeaver Visual Composer (CVSS 10.0, critical)
  - CVE-2024-21762 — Fortinet FortiOS (CVSS 9.8, critical)
  - (+13 more)
- Credential Access: OS Credential Dumping: LSASS Memory (T1003.001), Network Sniffing (T1040), …
- Tools: Credential theft: Mimikatz; Remote management (RMM) tools: NetSupport, ScreenConnect; …
- Reference (backup link): https://www.ransomware.live/group/qilin
```

(Illustrative numbers and fictional victims. The HTML version is color-coded, with the
same details in cards.)

## ⏰ Running it daily

Two ways, both documented in [docs/operations.md](docs/operations.md):

- ☁️ **Cloud Routine on claude.ai** (no machine of your own): a scheduled Claude Code
  session runs the pipeline, commits the state file, writes the AI analyst notes, and emails
  the HTML digest (inline + attached) through the Gmail connector — every run, clean ones
  included, so a missing email always means something broke. On heavy days (report over
  25 KB) the email body is a short overview (`--overview-out`) and the full report travels
  as the attachment. The instructions to paste into the Routine are in
  [ops/routine_prompt.md](ops/routine_prompt.md); the setup (network allowlist, API key,
  GitHub App, email) is in the [Cloud Routine runbook](docs/operations.md#cloud-routine-claudeai).
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

Phase 1 complete; Phase 2 well underway — ransomware.live (API PRO), CISA KEV, Have I Been
Pwned and VulnCheck KEV collectors live and verified against the real sources; running
daily as a cloud Routine with trends, threat-actor profiles and AI analyst notes. See
[docs/roadmap.md](docs/roadmap.md) for current status and what's next.

## 📄 License

[MIT](LICENSE) — do good things with it. 🙂
