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
from daily_darkweb.interface.render_html import render_html
from tests.conftest import make_item


def _report(alerts: list[Alert], observations: list[Alert]) -> Report:
    return Report(
        generated_at=datetime(2026, 7, 27, tzinfo=UTC),
        collector_results=[
            CollectResult(source="ransomware_live", status=CollectionStatus.OK, items=[])
        ],
        alerts=alerts,
        observations=observations,
    )


def test_hostile_content_is_escaped_not_executed() -> None:
    item = make_item(
        title="<script>alert(1)</script>",
        body="<img src=x onerror=alert(2)>",
        sector=None,
        country=None,
        victim_domain=None,
    )
    alert = Alert(
        item=item,
        matches=[Match(field=MatchField.ORG, watch_value="x", matched_text="x")],
        score=63,
        severity=Severity.MEDIUM,
    )
    html = render_html(_report(alerts=[alert], observations=[]))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "onerror=" not in html or "&lt;img" in html


def test_reference_link_and_due_date_present() -> None:
    item = make_item(
        source="cisa_kev",
        external_id="CVE-2026-3333",
        title="CVE-2026-3333: X",
        reference_url="https://nvd.nist.gov/vuln/detail/CVE-2026-3333",
        due_date=datetime(2026, 8, 5, tzinfo=UTC),
        sector=None,
        country=None,
        victim_domain=None,
    )
    alert = Alert(item=item, matches=[], score=45, severity=Severity.MEDIUM)
    html = render_html(_report(alerts=[], observations=[alert]))
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-3333" in html
    assert "Patch by: 2026-08-05" in html


def test_empty_sections_render_without_crashing() -> None:
    html = render_html(_report(alerts=[], observations=[]))
    assert "<title>Daily Darkweb digest</title>" in html
    assert "Nothing new here this run." in html
    assert "No new signals since last run." in html


def test_collector_failure_shown_as_failed_not_ok() -> None:
    report = _report(alerts=[], observations=[]).model_copy(
        update={
            "collector_results": [
                CollectResult(
                    source="ransomware_live", status=CollectionStatus.FAILED, error="boom"
                )
            ]
        }
    )
    html = render_html(report)
    assert "FAILED" in html
    assert "boom" in html
