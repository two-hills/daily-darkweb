from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from daily_darkweb.core.models import (
    Alert,
    AnalystNotes,
    CollectionStatus,
    CollectResult,
    DailySummary,
    KevEntry,
    Match,
    MatchField,
    Report,
    Severity,
)
from daily_darkweb.core.trends import compute_trends
from daily_darkweb.interface.render import render_markdown
from tests.conftest import make_item


def _obs(**overrides: object) -> Alert:
    item = make_item(**overrides)
    return Alert(item=item, matches=[], score=45, severity=Severity.MEDIUM)


def _report(alerts: list[Alert], observations: list[Alert]) -> Report:
    return Report(
        generated_at=datetime(2026, 7, 27, tzinfo=UTC),
        collector_results=[
            CollectResult(source="ransomware_live", status=CollectionStatus.OK, items=[]),
            CollectResult(source="cisa_kev", status=CollectionStatus.OK, items=[]),
        ],
        alerts=alerts,
        observations=observations,
    )


def test_unmatched_kev_item_appears_in_vulnerability_watch_not_buried() -> None:
    # 11 ransomware observations (one over the top-10 landscape cutoff) plus one unmatched
    # CVE — the CVE must still show up in full, not get crowded out by ransomware volume.
    ransomware_obs = [
        _obs(
            source="ransomware_live",
            external_id=f"r{i}",
            title=f"Victim {i}",
            sector=None,
            country=None,
            victim_domain=None,
        )
        for i in range(11)
    ]
    kev_obs = _obs(
        source="cisa_kev",
        external_id="CVE-2026-9999",
        title="CVE-2026-9999: Some RCE",
        sector=None,
        country=None,
        victim_domain=None,
    )
    report = _report(alerts=[], observations=[*ransomware_obs, kev_obs])
    rendered = render_markdown(report)
    assert "CVE-2026-9999" in rendered
    assert "## Vulnerability watch (1)" in rendered


def test_empty_vulnerability_watch_says_so() -> None:
    report = _report(alerts=[], observations=[])
    rendered = render_markdown(report)
    assert "No additional exploited CVEs outside your watchlist this run." in rendered


def test_due_date_rendered_for_kev_alert() -> None:
    item = make_item(
        source="cisa_kev",
        external_id="CVE-2026-1111",
        title="CVE-2026-1111: X",
        due_date=datetime(2026, 8, 1, tzinfo=UTC),
        sector=None,
        country=None,
        victim_domain=None,
    )
    alert = Alert(
        item=item,
        matches=[Match(field=MatchField.KEYWORD, watch_value="x", matched_text="x")],
        score=68,
        severity=Severity.HIGH,
    )
    rendered = render_markdown(_report(alerts=[alert], observations=[]))
    assert "Patch by: 2026-08-01" in rendered


def test_matched_kev_alert_not_duplicated_in_vulnerability_watch() -> None:
    item = make_item(
        source="cisa_kev",
        external_id="CVE-2026-2222",
        title="CVE-2026-2222: matched",
        sector=None,
        country=None,
        victim_domain=None,
    )
    alert = Alert(
        item=item,
        matches=[Match(field=MatchField.KEYWORD, watch_value="x", matched_text="x")],
        score=68,
        severity=Severity.HIGH,
    )
    rendered = render_markdown(_report(alerts=[alert], observations=[]))
    assert rendered.count("CVE-2026-2222") == 1


def test_collector_failure_surfaced() -> None:
    report = _report(alerts=[], observations=[])
    report = report.model_copy(
        update={
            "collector_results": [
                CollectResult(source="cisa_kev", status=CollectionStatus.FAILED, error="timeout")
            ]
        }
    )
    rendered = render_markdown(report)
    assert "FAILED" in rendered
    assert "all-clear" in rendered


def _history() -> list[DailySummary]:
    today = date(2026, 7, 27)
    return [
        DailySummary(day=today - timedelta(days=13), ransomware_claims=4, groups={"akira": 4}),
        DailySummary(
            day=today,
            ransomware_claims=6,
            groups={"akira": 2, "qilin": 4},
            countries={"TH": 2},
            kev_added=[KevEntry(cve_id="CVE-2026-7777", title="t", due_date=date(2026, 7, 30))],
        ),
    ]


def test_ai_notes_are_labelled_and_rendered() -> None:
    notes = AnalystNotes(
        headline="Edge devices under fire", points=["KEV doubled."], actions=["Patch gateways."]
    )
    report = _report(alerts=[], observations=[]).model_copy(update={"analyst_notes": notes})
    rendered = render_markdown(report)
    assert "## AI analyst notes (AI generated)" in rendered
    assert "may be wrong" in rendered
    assert "**Edge devices under fire**" in rendered
    assert "- KEV doubled." in rendered
    assert "Recommended actions:" in rendered
    assert "Caveats:" not in rendered  # empty lists render no heading
    # Notes sit above the sourced items so the summary is read first.
    assert rendered.index("AI analyst notes") < rendered.index("## Watchlist alerts")


def test_unavailable_notes_are_explained() -> None:
    report = _report(alerts=[], observations=[]).model_copy(
        update={"analyst_notes_unavailable": "notes failed validation"}
    )
    assert "Unavailable for this run: notes failed validation." in render_markdown(report)


def test_no_notes_section_unless_requested() -> None:
    assert "AI analyst notes" not in render_markdown(_report(alerts=[], observations=[]))


def test_trends_with_baseline_show_week_over_week_change() -> None:
    trends = compute_trends(_history(), date(2026, 7, 27), watch_countries=["TH"])
    report = _report(alerts=[], observations=[]).model_copy(update={"trends": trends})
    rendered = render_markdown(report)
    assert "## Trends (last 7 days)" in rendered
    assert "- Ransomware claims: 6 (prev 4, +50%)" in rendered
    assert "qilin 4 (prev 0, new)" in rendered
    assert "- New groups this window: qilin" in rendered
    assert "- Watchlist countries: 2 (prev 0, new) — TH 2 (prev 0, new)" in rendered
    assert "CVE-2026-7777 (due 2026-07-30)" in rendered


def test_trends_without_baseline_say_history_is_building() -> None:
    trends = compute_trends(_history()[1:], date(2026, 7, 27), watch_countries=[])
    report = _report(alerts=[], observations=[]).model_copy(update={"trends": trends})
    rendered = render_markdown(report)
    assert "- Ransomware claims: 6\n" in rendered
    assert "week-over-week comparison starts at 14 days" in rendered
