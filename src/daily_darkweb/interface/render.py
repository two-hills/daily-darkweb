"""Markdown digest rendering. Pure function of the Report; scraped text is shown as data."""

from __future__ import annotations

from collections import Counter

from daily_darkweb.core.models import Alert, CollectionStatus, Report

_TOP_OBSERVATIONS = 10


def render_markdown(report: Report) -> str:
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

    lines.append(f"## Watchlist alerts ({len(report.alerts)})")
    if report.alerts:
        for alert in report.alerts:
            lines.extend(_render_alert(alert))
    else:
        lines.append("No watchlist matches in new signals.")
    lines.append("")

    lines.append("## Threat landscape (new signals)")
    landscape = report.alerts + report.observations
    if landscape:
        actors = Counter(a.item.actor for a in landscape if a.item.actor)
        sectors = Counter(a.item.sector for a in landscape if a.item.sector)
        countries = Counter(a.item.country for a in landscape if a.item.country)
        lines.append(f"- New signals: {len(landscape)}")
        lines.append(f"- Most active groups: {_top(actors)}")
        lines.append(f"- Most hit sectors: {_top(sectors)}")
        lines.append(f"- Most hit countries: {_top(countries)}")
        lines.append("")
        lines.append(f"### Latest observations (top {_TOP_OBSERVATIONS})")
        for obs in report.observations[:_TOP_OBSERVATIONS]:
            context = ", ".join(x for x in (obs.item.sector, obs.item.country) if x)
            suffix = f" ({context})" if context else ""
            lines.append(f"- [{obs.severity.value}] {obs.item.title}{suffix}")
    else:
        lines.append("No new signals since last run.")
    lines.append("")
    return "\n".join(lines)


def _render_alert(alert: Alert) -> list[str]:
    matched = ", ".join(f"{m.field.value}={m.watch_value}" for m in alert.matches)
    lines = [
        f"### [{alert.severity.value.upper()} {alert.score}] {alert.item.title}",
        f"- Matched: {matched}",
        f"- Source: `{alert.item.source}` | published: {alert.item.published_at or 'unknown'}",
    ]
    if alert.item.reference_url:
        lines.append(f"- Reference: {alert.item.reference_url}")
    lines.append("")
    return lines


def _top(counter: Counter[str], n: int = 5) -> str:
    if not counter:
        return "n/a"
    return ", ".join(f"{name} ({count})" for name, count in counter.most_common(n))
