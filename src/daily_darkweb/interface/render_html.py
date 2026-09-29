"""Self-contained static HTML digest — open it directly in a browser, no server needed.

All scraped text is HTML-escaped before interpolation: item titles/bodies/actors/sectors
come from untrusted external sources and must never be able to inject markup or scripts.
AI analyst notes get the same treatment: they are model output, not trusted markup.
"""

from __future__ import annotations

from html import escape

from daily_darkweb.core.models import (
    Alert,
    CollectionStatus,
    CountDelta,
    GroupProfile,
    RawItem,
    Report,
    Trends,
)
from daily_darkweb.core.trends import DUE_SOON_DAYS, RANSOMWARE_SOURCE
from daily_darkweb.interface.digest_view import (
    AI_NOTES_DISCLAIMER,
    AI_NOTES_TITLE,
    PROFILES_NOTE,
    PROFILES_TITLE,
    SNIPPET_LIMIT,
    TOP_OBSERVATIONS,
    DigestView,
    build_view,
    defense_tactics,
    detail_lines,
    format_delta,
    history_note,
    item_description,
    profiles_by_group,
    tactic_line,
    tool_lines,
    victim_context,
)

_STYLE = """
:root {
  --bg: #f4f5f7; --card: #ffffff; --text: #1a1d23; --muted: #5b6270; --border: #e2e4e9;
  --crit: #b3261e; --high: #b5560a; --med: #8a6d00; --low: #2f5aa8; --info: #5b6270;
  --ai: #6b4fbb;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14161a; --card: #1d2026; --text: #e8e9ec; --muted: #9aa0ab; --border: #2c2f36;
    --crit: #ff6b60; --high: #ff9f43; --med: #e0c229; --low: #6fa8ff; --info: #9aa0ab;
    --ai: #b39dff;
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
.badge-ai { background: var(--ai); }
.ai-notes {
  background: var(--card); border: 1px dashed var(--ai); border-radius: 10px;
  padding: 4px 16px 12px; margin-top: 24px;
}
.ai-notes h2 { border-bottom: none; margin-top: 12px; }
.ai-headline { font-weight: 600; margin: 8px 0; }
.ai-subhead { color: var(--muted); font-size: 13px; font-weight: 600; margin: 12px 0 0; }
.ai-notes ul { margin: 6px 0; padding-left: 20px; font-size: 14px; }
.source-ai { font-style: italic; }
.detail { font-size: 13.5px; margin: 4px 0; }
.subhead { color: var(--muted); font-size: 13px; font-weight: 600; margin: 10px 0 0; }
.card ul { margin: 4px 0; padding-left: 20px; font-size: 13.5px; }
.snippet { color: var(--muted); }
"""


def render_html(report: Report) -> str:
    view = build_view(report)
    profiled = profiles_by_group(report)
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
        _render_notes(report),
        _render_trends(report.trends) if report.trends else "",
        _render_alert_section(
            "Watchlist alerts",
            "Signals matching your interests in config/watchlist.yaml.",
            view.alerts,
            profiled,
        ),
        _render_alert_section(
            "Vulnerability watch",
            "Every new confirmed-exploited CVE from CISA KEV, beyond your watchlist.",
            view.vulnerability_watch,
            profiled,
        ),
        _render_landscape(view),
        _render_profiles(report),
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


def _render_alert_section(
    title: str, note: str, alerts: list[Alert], profiled: dict[str, GroupProfile]
) -> str:
    html = f"<h2>{escape(title)} ({len(alerts)})</h2><p class='section-note'>{escape(note)}</p>"
    if not alerts:
        html += "<p class='empty'>Nothing new here this run.</p>"
        return html
    return html + "".join(_render_alert_card(a, profiled) for a in alerts)


def _link(url: str, inner_html: str) -> str:
    return f"<a href='{escape(url)}' target='_blank' rel='noopener'>{inner_html}</a>"


def _backup_link(url: str) -> str:
    return f"<p class='meta'>Reference (backup link): {_link(url, escape(url))}</p>"


def _render_alert_card(alert: Alert, profiled: dict[str, GroupProfile]) -> str:
    item = alert.item
    badge = (
        f"<span class='badge badge-{alert.severity.value}'>"
        f"{alert.severity.value} {alert.score}</span>"
    )
    lines = [f"<div class='card'><p class='card-title'>{badge}{escape(item.title)}</p>"]
    if alert.matches:
        matched = ", ".join(f"{m.field.value}={escape(m.watch_value)}" for m in alert.matches)
        lines.append(f"<p class='meta'>Matched: {matched}</p>")
    published = f"{item.published_at:%Y-%m-%d %H:%M} UTC" if item.published_at else "unknown"
    source_html = escape(item.source)
    lines.append(f"<p class='meta'>Source: <code>{source_html}</code> | published: {published}</p>")
    if item.due_date:
        lines.append(f"<p class='meta due'>Patch by: {item.due_date:%Y-%m-%d}</p>")
    if item.source == RANSOMWARE_SOURCE:
        lines.extend(_ransomware_details(item, profiled))
    else:
        lines.extend(f"<p class='detail'>{escape(line)}</p>" for line in detail_lines(item))
    if item.reference_url:
        lines.append(_backup_link(item.reference_url))
    lines.append("</div>")
    return "".join(lines)


def _ransomware_details(item: RawItem, profiled: dict[str, GroupProfile]) -> list[str]:
    lines = []
    context = victim_context(item)
    if context:
        lines.append(f"<p class='detail'><b>Victim:</b> {escape(context)}</p>")
    source_ai, description = item_description(item)
    if description:
        if source_ai:
            lines.append(
                "<p class='detail source-ai'><span class='badge badge-ai'>AI-generated "
                f"description</span>{escape(description)}</p>"
            )
        else:
            lines.append(
                f"<p class='detail'><b>Description (unverified):</b> {escape(description)}</p>"
            )
    if item.actor:
        suffix = " — profile below" if item.actor.lower() in profiled else ""
        lines.append(f"<p class='detail'><b>Group:</b> {escape(item.actor)}{suffix}</p>")
    return lines


def _render_profiles(report: Report) -> str:
    if not report.group_profiles and not report.profile_errors:
        return ""
    html = (
        f"<h2>{escape(PROFILES_TITLE)} ({len(report.group_profiles)})</h2>"
        f"<p class='section-note'>{escape(PROFILES_NOTE)}</p>"
    )
    for profile in report.group_profiles:
        html += _render_profile_card(profile)
    if report.profile_errors:
        missing = escape(", ".join(report.profile_errors))
        html += f"<p class='empty'>Profiles unavailable: {missing}.</p>"
    return html


def _render_profile_card(profile: GroupProfile) -> str:
    parts = [f"<div class='card'><p class='card-title'>{escape(profile.name)}</p>"]
    facts = []
    if profile.first_seen:
        facts.append(f"tracked since {profile.first_seen}")
    if profile.aliases:
        facts.append(f"also known as {', '.join(profile.aliases)}")
    if facts:
        parts.append(f"<p class='meta'>{escape('; '.join(facts))}</p>")
    if profile.description:
        parts.append(f"<p class='detail'>{escape(profile.description)}</p>")
    tactics = defense_tactics(profile)
    for tactic in tactics:
        if tactic.name.lower() == "initial access":
            items = "".join(
                f"<li><b>{escape(t.name)} ({escape(t.technique_id)})</b>"
                + (f": {escape(t.details)}" if t.details else "")
                + "</li>"
                for t in tactic.techniques
            )
            parts.append(f"<p class='subhead'>How they get in (Initial Access)</p><ul>{items}</ul>")
    others = [t for t in tactics if t.name.lower() != "initial access"]
    if others:
        items = "".join(f"<li>{escape(tactic_line(t))}</li>" for t in others)
        parts.append(f"<p class='subhead'>How they operate</p><ul>{items}</ul>")
    if not tactics:
        parts.append("<p class='meta'>No ATT&amp;CK technique mapping published yet.</p>")
    tools = tool_lines(profile)
    if tools:
        items = "".join(f"<li>{escape(line)}</li>" for line in tools)
        parts.append(f"<p class='subhead'>Tools</p><ul>{items}</ul>")
    if profile.reference_url:
        parts.append(_backup_link(profile.reference_url))
    parts.append("</div>")
    return "".join(parts)


def _render_notes(report: Report) -> str:
    if report.analyst_notes is None and report.analyst_notes_unavailable is None:
        return ""
    html = (
        "<section class='ai-notes'>"
        f"<h2>{escape(AI_NOTES_TITLE)} <span class='badge badge-ai'>AI generated</span></h2>"
        f"<p class='section-note'>{escape(AI_NOTES_DISCLAIMER)}</p>"
    )
    notes = report.analyst_notes
    if notes is None:
        reason = escape(report.analyst_notes_unavailable or "")
        return html + f"<p class='empty'>Unavailable for this run: {reason}.</p></section>"
    html += f"<p class='ai-headline'>{escape(notes.headline)}</p>" + _bullets(notes.points)
    for heading, entries in (("Recommended actions", notes.actions), ("Caveats", notes.caveats)):
        if entries:
            html += f"<p class='ai-subhead'>{heading}</p>" + _bullets(entries)
    return html + "</section>"


def _render_trends(trends: Trends) -> str:
    stats = [
        f"Ransomware claims: {format_delta(trends.ransomware_claims)}",
        f"Most active groups: {_deltas(trends.top_groups)}",
    ]
    if trends.new_groups:
        stats.append(f"New groups this window: {escape(', '.join(trends.new_groups))}")
    stats.append(f"Most hit sectors: {_deltas(trends.top_sectors)}")
    stats.append(f"Most hit countries: {_deltas(trends.top_countries)}")
    watch = f"Watchlist countries: {format_delta(trends.watch_countries)}"
    if trends.watch_country_breakdown:
        watch += f" — {_deltas(trends.watch_country_breakdown)}"
    stats.append(watch)
    stats.append(f"CISA KEV additions: {format_delta(trends.kev_added)}")
    if trends.kev_due_soon:
        due = ", ".join(f"{escape(e.cve_id)} (due {e.due_date})" for e in trends.kev_due_soon)
        label = f"KEV deadlines in the next {DUE_SOON_DAYS} days:"
        stats.append(f"<span class='due'>{label}</span> {due}")
    html = f"<h2>Trends (last {trends.window_days} days)</h2>"
    html += "".join(f"<p class='stats'>{line}</p>" for line in stats)
    return html + f"<p class='section-note'>{history_note(trends)}</p>"


def _bullets(entries: list[str]) -> str:
    return "<ul>" + "".join(f"<li>{escape(e)}</li>" for e in entries) + "</ul>"


def _deltas(deltas: list[CountDelta]) -> str:
    if not deltas:
        return "n/a"
    return ", ".join(f"{escape(d.name)} {format_delta(d)}" for d in deltas)


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
        _, description = item_description(obs.item, SNIPPET_LIMIT)
        snippet = f"<span class='snippet'> — {escape(description)}</span>" if description else ""
        html += f"<li>[{obs.severity.value}] {title}{suffix}{snippet}</li>"
    html += "</ul>"
    return html


def _top(pairs: list[tuple[str, int]]) -> str:
    if not pairs:
        return "n/a"
    return ", ".join(f"{escape(name)} ({count})" for name, count in pairs)
