from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime

from daily_darkweb.collectors.base import Collector
from daily_darkweb.core.dedup import dedupe, filter_new
from daily_darkweb.core.matching import match_item
from daily_darkweb.core.models import (
    Alert,
    CollectionStatus,
    GroupProfile,
    RawItem,
    Report,
    Watchlist,
)
from daily_darkweb.core.scoring import score_item
from daily_darkweb.core.trends import RANSOMWARE_SOURCE

ProfileFetcher = Callable[[str], Awaitable[GroupProfile]]


async def run_pipeline(
    collectors: Sequence[Collector],
    watchlist: Watchlist,
    seen_keys: frozenset[str],
    now: datetime,
) -> Report:
    results = await asyncio.gather(*(collector.collect() for collector in collectors))

    collected: list[RawItem] = []
    for result in results:
        if result.status is CollectionStatus.OK:
            collected.extend(result.items)

    new_items = filter_new(dedupe(collected), seen_keys)

    alerts: list[Alert] = []
    observations: list[Alert] = []
    for item in new_items:
        matches = match_item(item, watchlist)
        score, severity = score_item(item, matches, now)
        entry = Alert(item=item, matches=matches, score=score, severity=severity)
        (alerts if matches else observations).append(entry)

    alerts.sort(key=lambda a: a.score, reverse=True)
    observations.sort(key=lambda a: a.score, reverse=True)

    return Report(
        generated_at=now,
        collector_results=list(results),
        alerts=alerts,
        observations=observations,
    )


async def enrich_group_profiles(report: Report, fetch: ProfileFetcher, limit: int) -> Report:
    """Attach threat-actor profiles so readers never need to look the groups up
    themselves. Lookups run one at a time (a free API; politeness over speed) and are
    supplementary: a failure is noted in the report, never a collection failure."""
    profiles: list[GroupProfile] = []
    errors: list[str] = []
    for name in profile_candidates(report, limit):
        try:
            profiles.append(await fetch(name))
        except Exception as exc:
            errors.append(f"{name} ({type(exc).__name__})")
    return report.model_copy(update={"group_profiles": profiles, "profile_errors": errors})


def profile_candidates(report: Report, limit: int) -> list[str]:
    """Groups behind watchlist alerts first (highest score first), then the most active
    groups among the other new signals; case-insensitively unique, at most `limit`."""
    names: list[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        if name.lower() not in seen:
            seen.add(name.lower())
            names.append(name)

    for alert in report.alerts:
        if alert.item.source == RANSOMWARE_SOURCE and alert.item.actor:
            add(alert.item.actor)
    activity = Counter(
        o.item.actor
        for o in report.observations
        if o.item.source == RANSOMWARE_SOURCE and o.item.actor
    )
    for name, _ in sorted(activity.items(), key=lambda kv: (-kv[1], kv[0])):
        add(name)
    return names[:limit]
