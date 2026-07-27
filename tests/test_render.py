from __future__ import annotations

from datetime import UTC, datetime

from daily_darkweb.core.models import (
    Alert,
    CollectionStatus,
    CollectResult,
    Match,
    MatchField,
    Report,
    Severity,
)
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
