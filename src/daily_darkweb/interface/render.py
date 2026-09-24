"""Markdown digest rendering. Pure function of the Report; scraped text is shown as data."""

from __future__ import annotations

from daily_darkweb.core.models import Alert, CollectionStatus, CountDelta, Report, Trends
from daily_darkweb.core.trends import DUE_SOON_DAYS
from daily_darkweb.interface.digest_view import (
    AI_NOTES_DISCLAIMER,
    AI_NOTES_TITLE,
    TOP_OBSERVATIONS,
    build_view,
    format_delta,
    history_note,
)


def render_markdown(report: Report) -> str:
    view = build_view(report)
    lines: list[str] = [f"# Daily Darkweb digest — {report.generated_at:%Y-%m-%d %H:%M} UTC", ""]

    lines.append("## Collector status")
    for result in report.collector_results:
        if result.status is CollectionStatus.OK:
            lines.append(f"- `{result.source}`: OK ({len(result.items)} items)")
        else:
            lines.append(
                f"- `{result.source}`: **FAILED — could not determine, do not treat as "
                f"all-clear** ({result.error})"
            )
    lines.append("")

    lines.extend(_render_notes(report))
    if report.trends:
        lines.extend(_render_trends(report.trends))

    lines.append(f"## Watchlist alerts ({len(view.alerts)})")
    if view.alerts:
        for alert in view.alerts:
            lines.extend(_render_alert(alert))
    else:
        lines.append("No watchlist matches in new signals.")
    lines.append("")

    lines.append(f"## Vulnerability watch ({len(view.vulnerability_watch)})")
    lines.append("Every new confirmed-exploited CVE from CISA KEV, beyond your watchlist.")
    if view.vulnerability_watch:
        for alert in view.vulnerability_watch:
            lines.extend(_render_alert(alert))
    else:
        lines.append("No additional exploited CVEs outside your watchlist this run.")
    lines.append("")

    lines.append("## Threat landscape (ransomware, new signals)")
    if view.landscape_observations:
        lines.append(f"- New signals: {view.landscape_total}")
        lines.append(f"- Most active groups: {_top(view.top_actors)}")
        lines.append(f"- Most hit sectors: {_top(view.top_sectors)}")
        lines.append(f"- Most hit countries: {_top(view.top_countries)}")
        lines.append("")
        lines.append(f"### Latest observations (top {TOP_OBSERVATIONS})")
        for obs in view.landscape_observations[:TOP_OBSERVATIONS]:
            context = ", ".join(x for x in (obs.item.sector, obs.item.country) if x)
            suffix = f" ({context})" if context else ""
            lines.append(f"- [{obs.severity.value}] {obs.item.title}{suffix}")
    else:
        lines.append("No new signals since last run.")
    lines.append("")
    return "\n".join(lines)


def _render_alert(alert: Alert) -> list[str]:
    matched = ", ".join(f"{m.field.value}={m.watch_value}" for m in alert.matches)
    lines = [f"### [{alert.severity.value.upper()} {alert.score}] {alert.item.title}"]
    if matched:
        lines.append(f"- Matched: {matched}")
    lines.append(
        f"- Source: `{alert.item.source}` | published: {alert.item.published_at or 'unknown'}"
    )
    if alert.item.due_date:
        lines.append(f"- Patch by: {alert.item.due_date:%Y-%m-%d}")
    if alert.item.reference_url:
        lines.append(f"- Reference: {alert.item.reference_url}")
    lines.append("")
    return lines


def _render_notes(report: Report) -> list[str]:
    if report.analyst_notes is None and report.analyst_notes_unavailable is None:
        return []
    lines = [f"## {AI_NOTES_TITLE} (AI generated)", f"_{AI_NOTES_DISCLAIMER}_", ""]
    notes = report.analyst_notes
    if notes is None:
        lines.extend([f"Unavailable for this run: {report.analyst_notes_unavailable}.", ""])
        return lines
    lines.append(f"**{notes.headline}**")
    lines.extend(f"- {point}" for point in notes.points)
    for heading, entries in (("Recommended actions", notes.actions), ("Caveats", notes.caveats)):
        if entries:
            lines.extend(["", f"{heading}:"])
            lines.extend(f"- {entry}" for entry in entries)
    lines.append("")
    return lines


def _render_trends(trends: Trends) -> list[str]:
    lines = [
        f"## Trends (last {trends.window_days} days)",
        f"- Ransomware claims: {format_delta(trends.ransomware_claims)}",
        f"- Most active groups: {_deltas(trends.top_groups)}",
    ]
    if trends.new_groups:
        lines.append(f"- New groups this window: {', '.join(trends.new_groups)}")
    lines.append(f"- Most hit sectors: {_deltas(trends.top_sectors)}")
    lines.append(f"- Most hit countries: {_deltas(trends.top_countries)}")
    watch = f"- Watchlist countries: {format_delta(trends.watch_countries)}"
    if trends.watch_country_breakdown:
        watch += f" — {_deltas(trends.watch_country_breakdown)}"
    lines.append(watch)
    lines.append(f"- CISA KEV additions: {format_delta(trends.kev_added)}")
    if trends.kev_due_soon:
        due = ", ".join(f"{e.cve_id} (due {e.due_date})" for e in trends.kev_due_soon)
        lines.append(f"- KEV deadlines in the next {DUE_SOON_DAYS} days: {due}")
    lines.extend([f"- {history_note(trends)}", ""])
    return lines


def _deltas(deltas: list[CountDelta]) -> str:
    if not deltas:
        return "n/a"
    return ", ".join(f"{d.name} {format_delta(d)}" for d in deltas)


def _top(pairs: list[tuple[str, int]]) -> str:
    if not pairs:
        return "n/a"
    return ", ".join(f"{name} ({count})" for name, count in pairs)
