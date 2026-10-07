from __future__ import annotations

from datetime import UTC, datetime

from daily_darkweb.core.dedup import dedup_key
from daily_darkweb.core.models import (
    Alert,
    CollectionStatus,
    CollectResult,
    GroupProfile,
    Report,
    Severity,
    Watchlist,
)
from daily_darkweb.interface.render import render_markdown
from daily_darkweb.orchestration.pipeline import (
    enrich_group_profiles,
    profile_candidates,
    run_pipeline,
)
from tests.conftest import make_item


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


def _alert(actor: str, source: str = "ransomware_live", score: int = 50) -> Alert:
    item = make_item(external_id=f"{actor}-{score}-{source}", actor=actor, source=source)
    return Alert(item=item, matches=[], score=score, severity=Severity.MEDIUM)


def _report(alerts: list[Alert], observations: list[Alert]) -> Report:
    return Report(
        generated_at=datetime(2026, 9, 29, tzinfo=UTC),
        collector_results=[],
        alerts=alerts,
        observations=observations,
    )


def test_profile_candidates_put_alert_groups_first_then_most_active() -> None:
    report = _report(
        alerts=[_alert("chaos"), _alert("Qilin")],
        observations=[
            _alert("akira"),
            _alert("qilin", score=40),  # same group as an alert, different case
            _alert("play"),
            _alert("play", score=41),
            _alert("akira", score=42),
            _alert("akira", score=43),
            _alert("CVE-1", source="cisa_kev"),
        ],
    )
    assert profile_candidates(report, limit=4) == ["chaos", "Qilin", "akira", "play"]
    assert profile_candidates(report, limit=2) == ["chaos", "Qilin"]
    assert profile_candidates(report, limit=0) == []


async def test_enrichment_attaches_profiles_and_notes_failures() -> None:
    async def fetch(name: str) -> GroupProfile:
        if name == "play":
            raise RuntimeError("upstream down")
        return GroupProfile(name=name, description=f"{name} profile")

    report = _report(alerts=[_alert("qilin")], observations=[_alert("play")])
    enriched = await enrich_group_profiles(report, fetch, limit=5)
    assert [p.name for p in enriched.group_profiles] == ["qilin"]
    assert enriched.profile_errors == ["play (RuntimeError)"]
    assert enriched.collector_results == report.collector_results  # never a collection failure


async def test_a_cve_cisa_lists_is_reported_from_cisa_only(now: datetime) -> None:
    """VulnCheck and CISA can disagree for a day (sync lag); CISA's entry wins."""
    cisa = make_item(source="cisa_kev", external_id="CVE-2026-1", title="CVE-2026-1: X")
    both = make_item(source="vulncheck_kev", external_id="cve-2026-1", title="CVE-2026-1: X")
    only = make_item(source="vulncheck_kev", external_id="CVE-2026-2", title="CVE-2026-2: Y")
    report = await run_pipeline(
        [ok("cisa_kev", [cisa]), ok("vulncheck_kev", [both, only])],
        Watchlist(),
        frozenset(),
        now,
    )
    reported = sorted((a.item.source, a.item.external_id) for a in report.observations)
    assert reported == [("cisa_kev", "CVE-2026-1"), ("vulncheck_kev", "CVE-2026-2")]


async def test_cisa_entry_already_seen_still_suppresses_the_vulncheck_copy(now: datetime) -> None:
    cisa = make_item(source="cisa_kev", external_id="CVE-2026-1", title="CVE-2026-1: X")
    copy = make_item(source="vulncheck_kev", external_id="CVE-2026-1", title="CVE-2026-1: X")
    report = await run_pipeline(
        [ok("cisa_kev", [cisa]), ok("vulncheck_kev", [copy])],
        Watchlist(),
        frozenset({dedup_key(cisa)}),
        now,
    )
    assert report.alerts == [] and report.observations == []
