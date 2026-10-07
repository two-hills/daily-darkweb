from __future__ import annotations

from datetime import UTC, date, datetime

from daily_darkweb.core.models import (
    Alert,
    AnalystNotes,
    AttackTactic,
    AttackTechnique,
    CollectionStatus,
    CollectResult,
    DailySummary,
    ExploitedCve,
    GroupProfile,
    InfostealerExposure,
    KevEntry,
    Match,
    MatchField,
    Report,
    Severity,
)
from daily_darkweb.core.trends import compute_trends
from daily_darkweb.interface.render_html import render_html, render_html_overview
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
    assert "class='badge badge-ai'" in html
    assert ">AI generated</span>" in html
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
    # Descriptions read as one paragraph: line breaks from the source are folded.
    assert "AI-generated description</span>Regional optometry chain. Second line." in html
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


def test_profile_card_is_escaped_and_keeps_a_backup_link() -> None:
    profile = GroupProfile(
        name="<b>qilin</b>",
        description="<script>alert(1)</script>",
        tactics=[
            AttackTactic(
                tactic_id="TA0001",
                name="Initial Access",
                techniques=[
                    AttackTechnique(technique_id="T1078", name="Valid Accounts", details="<img>")
                ],
            )
        ],
        tools={"CredentialTheft": ["<i>Mimikatz</i>"]},
        reference_url="https://www.ransomware.live/group/qilin",
    )
    report = _report(alerts=[], observations=[]).model_copy(update={"group_profiles": [profile]})
    html = render_html(report)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "<b>qilin</b>" not in html
    assert "<i>Mimikatz</i>" not in html
    assert "How they get in (Initial Access)" in html
    assert "Reference (backup link): <a href='https://www.ransomware.live/group/qilin'" in html


def test_alert_card_shows_victim_description_and_group() -> None:
    item = make_item(
        body="Patient forms, 290 GB.",
        sector="Healthcare",
        country="US",
        victim_domain="clinic.example",
        reference_url="https://www.ransomware.live/id/x",
    )
    alert = Alert(item=item, matches=[], score=63, severity=Severity.MEDIUM)
    report = _report(alerts=[alert], observations=[]).model_copy(
        update={"group_profiles": [GroupProfile(name="QILIN")]}
    )
    html = render_html(report)
    assert "<b>Victim:</b> Healthcare · US · website clinic.example" in html
    assert "<b>Description (unverified):</b> Patient forms, 290 GB." in html
    assert "<b>Group:</b> qilin — profile below" in html  # matched case-insensitively
    assert "Reference (backup link): <a href='https://www.ransomware.live/id/x'" in html


def test_html_is_email_safe_no_css_variables() -> None:
    """The page doubles as the email body; Gmail and Outlook drop var(), which once
    erased cards and badges (white-on-white badge text) from the delivered email."""
    alert = Alert(
        item=make_item(body="[AI generated] Text."),
        matches=[],
        score=76,
        severity=Severity.HIGH,
    )
    report = _report(alerts=[alert], observations=[]).model_copy(
        update={
            "analyst_notes": AnalystNotes(headline="h", points=["p"]),
            "group_profiles": [GroupProfile(name="qilin", description="d")],
        }
    )
    html = render_html(report)
    assert "var(" not in html
    assert "--" not in html.split("<style>", 1)[1].split("</style>", 1)[0]
    # Badges carry their colours inline, so they survive clients that strip <style>.
    assert "<span class='badge badge-high' style='background:#b5560a;color:#ffffff'>" in html
    assert "style='background:#6b4fbb;color:#ffffff'>AI generated</span>" in html
    assert "style='background:#6b4fbb;color:#ffffff'>AI-generated description</span>" in html


def test_profile_card_lists_exploited_cves_and_activity_facts() -> None:
    profile = GroupProfile(
        name="qilin",
        first_seen=date(2022, 10, 8),
        victim_count=2342,
        exploited_cves=[
            ExploitedCve(cve_id="CVE-2024-21762", vendor="<b>Fortinet</b>", cvss=9.8),
        ],
    )
    report = _report(alerts=[], observations=[]).model_copy(update={"group_profiles": [profile]})
    html = render_html(report)
    assert "tracked since 2022-10-08; 2,342 victims claimed" in html
    assert "<p class='subhead'>Vulnerabilities they exploit</p>" in html
    assert "<li>CVE-2024-21762 — &lt;b&gt;Fortinet&lt;/b&gt; (CVSS 9.8)</li>" in html


def test_alert_card_shows_infostealer_exposure_and_press_link() -> None:
    item = make_item(
        infostealer=InfostealerExposure(third_parties=2),
        press_url="https://news.example/a?b=1&c=<x>",
    )
    alert = Alert(item=item, matches=[], score=63, severity=Severity.MEDIUM)
    html = render_html(_report(alerts=[alert], observations=[]))
    assert (
        "<b>Infostealer exposure:</b> 2 third-party accounts with credentials stolen by "
        "infostealer malware</p>"
    ) in html
    assert "Press coverage (backup link): <a href='https://news.example/a?b=1&amp;c=&lt;x&gt;'" in (
        html
    )


def _heavy_report() -> Report:
    alerts = [
        Alert(
            item=make_item(
                external_id=f"a{i}",
                title=f"<i>Victim {i}</i> claimed by qilin",
                body="A long unverified claim text that belongs in the attachment only.",
                reference_url=f"https://www.ransomware.live/id/{i}",
            ),
            matches=[Match(field=MatchField.SECTOR, watch_value="Healthcare", matched_text="x")],
            score=70 - i,
            severity=Severity.HIGH,
        )
        for i in range(20)
    ]
    kev = Alert(
        item=make_item(
            source="cisa_kev",
            external_id="CVE-2026-4444",
            title="CVE-2026-4444: Gateway RCE",
            body="Vendor: Acme | Product: Gateway",
            due_date=datetime(2026, 8, 10, tzinfo=UTC),
            actor=None,
            sector=None,
            country=None,
            reference_url="https://nvd.nist.gov/vuln/detail/CVE-2026-4444",
        ),
        matches=[],
        score=60,
        severity=Severity.MEDIUM,
    )
    return _report(alerts=alerts, observations=[kev]).model_copy(
        update={
            "collector_results": [
                CollectResult(source="ransomware_live", status=CollectionStatus.OK, items=[]),
                CollectResult(source="cisa_kev", status=CollectionStatus.FAILED, error="boom"),
            ],
            "analyst_notes": AnalystNotes(headline="Busy day for qilin", points=["p"]),
            "group_profiles": [GroupProfile(name="qilin", description="Profile text.")],
        }
    )


def test_overview_is_a_compact_link_free_summary_of_a_heavy_report() -> None:
    report = _heavy_report()
    overview = render_html_overview(report)
    full = render_html(report)

    assert "<h1>Daily Darkweb digest — overview</h1>" in overview
    assert "The attached HTML report has every detail" in overview
    assert "FAILED — could not determine, do not treat as all-clear (boom)" in overview
    assert "Busy day for qilin" in overview  # AI notes lead, with their label
    assert ">AI generated</span>" in overview
    assert "<h2>Watchlist alerts (20)</h2>" in overview
    assert "&lt;i&gt;Victim 0&lt;/i&gt; claimed by qilin" in overview  # escaped
    assert "Healthcare Services · TH · matched Healthcare" in overview
    assert "+5 more in the attached report" in overview  # 15 shown
    assert "CVE-2026-4444: Gateway RCE" in overview
    assert "patch by 2026-08-10" in overview
    assert "Threat actor profiles in the attached report: qilin" in overview
    # Details stay in the attachment, and the overview carries no links at all.
    assert "A long unverified claim text" not in overview
    assert "Profile text." not in overview
    assert "<a " not in overview
    assert "var(" not in overview
    assert len(overview) < len(full) / 2


def test_breach_watch_card_and_overview_line() -> None:
    item = make_item(
        source="hibp",
        external_id="AngelOne",
        title="Angel <One>: 6,765,054 accounts exposed",
        body="Exposed data: Email addresses",
        summary="Data <b>posted</b> to a forum.",
        actor=None,
        sector=None,
        country="IN",
        reference_url="https://haveibeenpwned.com/Breach/AngelOne",
    )
    report = _report(
        alerts=[], observations=[Alert(item=item, matches=[], score=45, severity=Severity.MEDIUM)]
    )
    report = report.model_copy(
        update={
            "collector_results": [
                *report.collector_results,
                CollectResult(source="hibp", status=CollectionStatus.OK),
            ]
        }
    )
    html = render_html(report)
    assert "<h2>Breach watch (1)</h2>" in html
    assert "Angel &lt;One&gt;: 6,765,054 accounts exposed" in html
    assert "<b>Summary:</b> Data &lt;b&gt;posted&lt;/b&gt; to a forum.</p>" in html
    overview = render_html_overview(report)
    assert "<h2>Breach watch (1)</h2>" in overview
    assert "Angel &lt;One&gt;: 6,765,054 accounts exposed" in overview
    assert "Data &lt;b&gt;posted" not in overview  # summaries stay in the attachment
