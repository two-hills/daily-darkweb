"""Markdown digest rendering. Pure function of the Report; scraped text is shown as data."""

from __future__ import annotations

from daily_darkweb.core.models import Alert, CollectionStatus, Report
from daily_darkweb.interface.digest_view import TOP_OBSERVATIONS, build_view


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


def _top(pairs: list[tuple[str, int]]) -> str:
    if not pairs:
        return "n/a"
    return ", ".join(f"{name} ({count})" for name, count in pairs)
