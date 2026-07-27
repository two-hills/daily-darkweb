"""Self-contained static HTML digest — open it directly in a browser, no server needed.

All scraped text is HTML-escaped before interpolation: item titles/bodies/actors/sectors
come from untrusted external sources and must never be able to inject markup or scripts.
"""

from __future__ import annotations

from html import escape

from daily_darkweb.core.models import Alert, CollectionStatus, Report
from daily_darkweb.interface.digest_view import TOP_OBSERVATIONS, DigestView, build_view

_STYLE = """
:root {
  --bg: #f4f5f7; --card: #ffffff; --text: #1a1d23; --muted: #5b6270; --border: #e2e4e9;
  --crit: #b3261e; --high: #b5560a; --med: #8a6d00; --low: #2f5aa8; --info: #5b6270;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14161a; --card: #1d2026; --text: #e8e9ec; --muted: #9aa0ab; --border: #2c2f36;
    --crit: #ff6b60; --high: #ff9f43; --med: #e0c229; --low: #6fa8ff; --info: #9aa0ab;
  }
}
* { box-sizing: border-box; }
body {
  background: var(--bg); color: var(--text); margin: 0; padding: 24px 16px 64px;
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
main { max-width: 780px; margin: 0 auto; }
h1 { font-size: 22px; margin: 0 0 4px; }
.subtitle { color: var(--muted); font-size: 13px; margin-bottom: 28px; }
h2 {
  font-size: 16px; margin: 32px 0 4px; padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}
.section-note { color: var(--muted); font-size: 13px; margin: 0 0 12px; }
.card {
  background: var(--card); border: 1px solid var(--border); border-radius: 10px;
  padding: 14px 16px; margin-bottom: 10px;
}
.card-title { font-weight: 600; font-size: 14px; margin: 0 0 6px; }
.card-title a { color: inherit; text-decoration: none; }
.card-title a:hover { text-decoration: underline; }
.meta { color: var(--muted); font-size: 12.5px; margin: 2px 0; }
.badge {
  display: inline-block; font-size: 11px; font-weight: 700; letter-spacing: .02em;
  padding: 2px 8px; border-radius: 999px; margin-right: 8px; text-transform: uppercase;
  color: #fff;
}
.badge-critical { background: var(--crit); }
.badge-high { background: var(--high); }
.badge-medium { background: var(--med); color: #1a1d23; }
.badge-low { background: var(--low); }
.badge-info { background: var(--info); }
.due { color: var(--crit); font-weight: 600; }
.empty { color: var(--muted); font-style: italic; }
.fail { color: var(--crit); font-weight: 600; }
.ok { color: var(--muted); }
.stats { color: var(--muted); font-size: 13px; margin: 4px 0; }
ul.plain { list-style: none; padding: 0; margin: 8px 0; }
ul.plain li { padding: 4px 0; font-size: 13.5px; border-bottom: 1px dotted var(--border); }
"""


def render_html(report: Report) -> str:
    view = build_view(report)
    header = (
        "<h1>Daily Darkweb digest</h1>"
        f"<p class='subtitle'>{report.generated_at:%Y-%m-%d %H:%M} UTC</p>"
    )
    parts: list[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        "<title>Daily Darkweb digest</title>",
        f"<style>{_STYLE}</style></head><body><main>",
        header,
        _render_collector_status(report),
        _render_alert_section(
            "Watchlist alerts",
            "Signals matching your interests in config/watchlist.yaml.",
            view.alerts,
        ),
        _render_alert_section(
            "Vulnerability watch",
            "Every new confirmed-exploited CVE from CISA KEV, beyond your watchlist.",
            view.vulnerability_watch,
        ),
        _render_landscape(view),
        "</main></body></html>",
    ]
    return "".join(parts)


def _render_collector_status(report: Report) -> str:
    rows = []
    for result in report.collector_results:
        if result.status is CollectionStatus.OK:
            rows.append(
                f"<li class='ok'><code>{escape(result.source)}</code>: "
                f"OK ({len(result.items)} items)</li>"
            )
        else:
            rows.append(
                f"<li class='fail'><code>{escape(result.source)}</code>: FAILED — could not "
                f"determine, do not treat as all-clear ({escape(result.error or '')})</li>"
            )
    return "<h2>Collector status</h2><ul class='plain'>" + "".join(rows) + "</ul>"


def _render_alert_section(title: str, note: str, alerts: list[Alert]) -> str:
    html = f"<h2>{escape(title)} ({len(alerts)})</h2><p class='section-note'>{escape(note)}</p>"
    if not alerts:
        html += "<p class='empty'>Nothing new here this run.</p>"
        return html
    return html + "".join(_render_alert_card(a) for a in alerts)


def _link(url: str, inner_html: str) -> str:
    return f"<a href='{escape(url)}' target='_blank' rel='noopener'>{inner_html}</a>"


def _render_alert_card(alert: Alert) -> str:
    item = alert.item
    badge = (
        f"<span class='badge badge-{alert.severity.value}'>"
        f"{alert.severity.value} {alert.score}</span>"
    )
    title_html = escape(item.title)
    if item.reference_url:
        title_html = _link(item.reference_url, title_html)
    lines = [f"<div class='card'><p class='card-title'>{badge}{title_html}</p>"]
    if alert.matches:
        matched = ", ".join(f"{m.field.value}={escape(m.watch_value)}" for m in alert.matches)
        lines.append(f"<p class='meta'>Matched: {matched}</p>")
    published = f"{item.published_at:%Y-%m-%d}" if item.published_at else "unknown"
    source_html = escape(item.source)
    lines.append(f"<p class='meta'>Source: <code>{source_html}</code> | published: {published}</p>")
    if item.due_date:
        lines.append(f"<p class='meta due'>Patch by: {item.due_date:%Y-%m-%d}</p>")
    if item.body:
        lines.append(f"<p class='meta'>{escape(item.body).replace(chr(10), '<br>')}</p>")
    lines.append("</div>")
    return "".join(lines)


def _render_landscape(view: DigestView) -> str:
    html = "<h2>Threat landscape (ransomware, new signals)</h2>"
    if not view.landscape_observations:
        return html + "<p class='empty'>No new signals since last run.</p>"
    html += f"<p class='stats'>New signals: {view.landscape_total}</p>"
    html += f"<p class='stats'>Most active groups: {_top(view.top_actors)}</p>"
    html += f"<p class='stats'>Most hit sectors: {_top(view.top_sectors)}</p>"
    html += f"<p class='stats'>Most hit countries: {_top(view.top_countries)}</p>"
    html += f"<h3>Latest observations (top {TOP_OBSERVATIONS})</h3><ul class='plain'>"
    for obs in view.landscape_observations[:TOP_OBSERVATIONS]:
        context = ", ".join(x for x in (obs.item.sector, obs.item.country) if x)
        suffix = f" ({escape(context)})" if context else ""
        title = escape(obs.item.title)
        if obs.item.reference_url:
            title = _link(obs.item.reference_url, title)
        html += f"<li>[{obs.severity.value}] {title}{suffix}</li>"
    html += "</ul>"
    return html


def _top(pairs: list[tuple[str, int]]) -> str:
    if not pairs:
        return "n/a"
    return ", ".join(f"{escape(name)} ({count})" for name, count in pairs)
