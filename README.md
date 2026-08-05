# 🌒 daily-darkweb

A clearnet-first threat intelligence digest for security professionals who want to stay
current on real-world dark-web-derived activity — ransomware victim claims and vulnerabilities
confirmed exploited in the wild — without operating collectors on dark-web infrastructure. 🕵️

Run it daily and get a markdown briefing: what's new, what matches your interests, and what
requires attention today. ☕📰

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
    -> markdown / JSON digest
```

- 🚫 **Fail-closed.** A collector error is surfaced in the digest as an explicit failure
  ("do not treat as all-clear") — never silently dropped or reported as a clean run.
- 🎯 **Deterministic.** No AI in the scoring path. Same input always produces the same score;
  scraped content is matched as data, never interpreted as instructions.
- 🛡️ **Metadata only.** Never ingests leaked payloads, credentials, or stolen data.

## 📡 Sources

| Source | Signal | Auth |
|---|---|---|
| [ransomware.live](https://ransomware.live) 💀 | Ransomware group victim-claim metadata | none |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) 🚨 | Vulnerabilities confirmed exploited in the wild | none |

Both are free and require no API key. See [docs/roadmap.md](docs/roadmap.md) for planned
sources (breach exposure, leak-site/paste watch, LLM triage). 🗺️

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
technology keywords, sectors, and countries. No owned domains are required; the project ships
in awareness mode by default. Collector toggles live in [config/sources.yaml](config/sources.yaml).

## 📋 Sample output

```
## Watchlist alerts (3)
### [HIGH 73] CVE-2026-25089: Fortinet FortiSandbox OS Command Injection Vulnerability
- Matched: keyword=fortinet
- Source: `cisa_kev` | published: 2026-07-16
- Reference: https://nvd.nist.gov/vuln/detail/CVE-2026-25089

## Threat landscape (new signals)
- New signals: 124
- Most active groups: qilin (20), thegentlemen (20), dragonforce (10)
- Most hit sectors: Business Services (17), Manufacturing (13), Technology (8)
```

## ⏰ Running it daily

See [docs/operations.md](docs/operations.md) for a launchd-based runbook (recommended for an
always-on machine 🖥️) that archives digests and notifies only when there's something to see.

## 📧 Email notifications (optional)

`--email` sends the HTML digest by SMTP (inline body + attachment) when there are alerts
or a collector failure — silent on clean runs. Off by default; set `SMTP_USER`,
`SMTP_PASSWORD`, `EMAIL_TO` in `.env` (see `.env.example`) to enable. Delivery is a
convenience channel — the archived `.md`/`.html` files stay authoritative either way.

## 🧪 Development

```sh
uv run ruff check . && uv run ruff format --check .   # lint + format
uv run mypy                                            # strict types
uv run pytest -q                                       # tests (mocked HTTP only, no live calls)
```

See [CLAUDE.md](CLAUDE.md) for locked project decisions and [docs/architecture.md](docs/architecture.md)
for the layered design and threat model.

## 📈 Status

Phase 1 and initial Phase 2 collectors complete and verified against live sources. See
[docs/roadmap.md](docs/roadmap.md) for current status and what's next.

## 📄 License

[MIT](LICENSE) — do good things with it. 🙂
