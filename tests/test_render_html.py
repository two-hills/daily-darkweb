from __future__ import annotations

from datetime import UTC, date, datetime

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


def test_ai_notes_are_escaped_and_labelled() -> None:
    notes = AnalystNotes(
        headline="<b>not bold</b>",
        points=["<script>alert(1)</script>"],
        caveats=["<img src=x onerror=alert(2)>"],
    )
    report = _report(alerts=[], observations=[]).model_copy(update={"analyst_notes": notes})
    html = render_html(report)
    assert "<script>alert(1)</script>" not in html
    assert "<b>not bold</b>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x" not in html
    assert "<span class='badge badge-ai'>AI generated</span>" in html
    assert "may be wrong" in html


def test_unavailable_notes_are_shown_not_hidden() -> None:
    report = _report(alerts=[], observations=[]).model_copy(
        update={"analyst_notes_unavailable": "notes failed validation"}
    )
    assert "Unavailable for this run: notes failed validation." in render_html(report)


def test_source_ai_description_gets_badge_and_marker_removed() -> None:
    item = make_item(body="[AI generated] Regional optometry chain.\nSecond line.")
    alert = Alert(item=item, matches=[], score=56, severity=Severity.MEDIUM)
    html = render_html(_report(alerts=[alert], observations=[]))
    assert "AI-generated description</span>Regional optometry chain.<br>Second line." in html
    assert "[AI generated]" not in html


def test_plain_source_description_has_no_ai_badge() -> None:
    alert = Alert(
        item=make_item(body="Stolen data: 7 GB."), matches=[], score=56, severity=Severity.MEDIUM
    )
    html = render_html(_report(alerts=[alert], observations=[]))
    assert "Stolen data: 7 GB." in html
    assert "AI-generated description" not in html


def test_trends_section_lists_kev_deadlines() -> None:
    today = date(2026, 7, 27)
    history = [
        DailySummary(
            day=today,
            ransomware_claims=3,
            groups={"<b>gang</b>": 3},
            kev_added=[KevEntry(cve_id="CVE-2026-8888", title="t", due_date=date(2026, 7, 28))],
        )
    ]
    report = _report(alerts=[], observations=[]).model_copy(
        update={"trends": compute_trends(history, today, watch_countries=[])}
    )
    html = render_html(report)
    assert "<h2>Trends (last 7 days)</h2>" in html
    assert "KEV deadlines in the next 7 days:</span> CVE-2026-8888 (due 2026-07-28)" in html
    assert "&lt;b&gt;gang&lt;/b&gt; 3" in html  # scraped group names stay escaped
