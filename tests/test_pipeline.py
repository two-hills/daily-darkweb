from __future__ import annotations

from datetime import datetime

from tests.conftest import make_item

from daily_darkweb.core.dedup import dedup_key
from daily_darkweb.core.models import (
    CollectionStatus,
    CollectResult,
    Severity,
    Watchlist,
)
from daily_darkweb.interface.render import render_markdown
from daily_darkweb.orchestration.pipeline import run_pipeline


class StubCollector:
    def __init__(self, name: str, result: CollectResult) -> None:
        self.name = name
        self._result = result

    async def collect(self) -> CollectResult:
        return self._result


def ok(name: str, items: list) -> StubCollector:  # type: ignore[type-arg]
    return StubCollector(name, CollectResult(source=name, status=CollectionStatus.OK, items=items))


def failed(name: str) -> StubCollector:
    return StubCollector(
        name,
        CollectResult(source=name, status=CollectionStatus.FAILED, error="timeout"),
    )


async def test_matched_items_become_alerts(now: datetime) -> None:
    item = make_item(victim_domain="example.com")
    report = await run_pipeline(
        [ok("ransomware_live", [item])],
        Watchlist(domains=["example.com"]),
        frozenset(),
        now,
    )
    assert len(report.alerts) == 1
    assert report.alerts[0].severity is Severity.CRITICAL
    assert report.observations == []


async def test_failure_is_surfaced_not_swallowed(now: datetime) -> None:
    report = await run_pipeline([failed("ransomware_live")], Watchlist(), frozenset(), now)
    assert report.has_failures
    rendered = render_markdown(report)
    assert "FAILED" in rendered
    assert "all-clear" in rendered


async def test_seen_items_filtered_and_deduped(now: datetime) -> None:
    item = make_item(external_id="seen-one", victim_domain=None, sector=None, country=None)
    dup = make_item(external_id="fresh", title="A")
    dup2 = make_item(external_id="fresh", title="B")
    report = await run_pipeline(
        [ok("ransomware_live", [item, dup, dup2])],
        Watchlist(),
        frozenset({dedup_key(item)}),
        now,
    )
    assert len(report.alerts) + len(report.observations) == 1


async def test_alerts_sorted_by_score(now: datetime) -> None:
    strong = make_item(external_id="a", victim_domain="example.com")
    weak = make_item(
        external_id="b",
        victim_domain=None,
        title="x",
        body="",
        sector="Healthcare Services",
        country=None,
    )
    report = await run_pipeline(
        [ok("ransomware_live", [weak, strong])],
        Watchlist(domains=["example.com"], sectors=["Healthcare"]),
        frozenset(),
        now,
    )
    scores = [a.score for a in report.alerts]
    assert scores == sorted(scores, reverse=True)
