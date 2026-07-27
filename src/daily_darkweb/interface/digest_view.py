"""Format-agnostic digest view model, shared by the markdown and HTML renderers.

Splits observations by source so a handful of new CVEs never get crowded out of a
shared top-N slot by ransomware volume (both are useful, but very different in scale).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from daily_darkweb.core.models import Alert, Report

_VULN_SOURCE = "cisa_kev"
TOP_OBSERVATIONS = 10
TOP_STATS = 5


@dataclass(frozen=True)
class DigestView:
    alerts: list[Alert]
    vulnerability_watch: list[Alert]
    landscape_observations: list[Alert]
    landscape_total: int
    top_actors: list[tuple[str, int]]
    top_sectors: list[tuple[str, int]]
    top_countries: list[tuple[str, int]]


def build_view(report: Report) -> DigestView:
    vuln_watch = [a for a in report.observations if a.item.source == _VULN_SOURCE]
    landscape = [a for a in report.observations if a.item.source != _VULN_SOURCE]
    actors = Counter(a.item.actor for a in landscape if a.item.actor)
    sectors = Counter(a.item.sector for a in landscape if a.item.sector)
    countries = Counter(a.item.country for a in landscape if a.item.country)
    return DigestView(
        alerts=report.alerts,
        vulnerability_watch=sorted(vuln_watch, key=lambda a: a.score, reverse=True),
        landscape_observations=landscape,
        landscape_total=len(landscape),
        top_actors=actors.most_common(TOP_STATS),
        top_sectors=sectors.most_common(TOP_STATS),
        top_countries=countries.most_common(TOP_STATS),
    )
