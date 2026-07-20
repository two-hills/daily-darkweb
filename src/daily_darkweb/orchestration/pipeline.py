from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import datetime

from daily_darkweb.collectors.base import Collector
from daily_darkweb.core.dedup import dedupe, filter_new
from daily_darkweb.core.matching import match_item
from daily_darkweb.core.models import (
    Alert,
    CollectionStatus,
    RawItem,
    Report,
    Watchlist,
)
from daily_darkweb.core.scoring import score_item


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
