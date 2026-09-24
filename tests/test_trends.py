from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from daily_darkweb.core.models import (
    Alert,
    CollectionStatus,
    CollectResult,
    DailySummary,
    KevEntry,
    Report,
    Severity,
)
from daily_darkweb.core.trends import compute_trends, merge_history, summarize
from tests.conftest import make_item

TODAY = date(2026, 9, 24)


def _alert(**overrides: object) -> Alert:
    return Alert(item=make_item(**overrides), matches=[], score=45, severity=Severity.MEDIUM)


def _report(alerts: list[Alert], failed: bool = False) -> Report:
    status = CollectionStatus.FAILED if failed else CollectionStatus.OK
    return Report(
        generated_at=datetime(2026, 9, 24, 1, 0, tzinfo=UTC),
        collector_results=[CollectResult(source="ransomware_live", status=status)],
        alerts=alerts[:1],
        observations=alerts[1:],
    )


def _day(offset: int, **fields: object) -> DailySummary:
    return DailySummary.model_validate({"day": TODAY - timedelta(days=offset), **fields})


class TestSummarize:
    def test_counts_new_signals_by_source(self) -> None:
        report = _report(
            [
                _alert(external_id="r1", actor="qilin", sector="Healthcare", country="th"),
                _alert(external_id="r2", actor="qilin", sector=None, country="JP"),
                _alert(external_id="r3", actor=None, sector="Manufacturing", country=None),
                _alert(
                    source="cisa_kev",
                    external_id="CVE-2026-1",
                    title="CVE-2026-1: Gateway RCE",
                    due_date=datetime(2026, 10, 1, tzinfo=UTC),
                ),
            ]
        )
        summary = summarize(report, TODAY)
        assert summary.day == TODAY
        assert summary.complete is True
        assert summary.ransomware_claims == 3
        assert summary.groups == {"qilin": 2}
        assert summary.sectors == {"Healthcare": 1, "Manufacturing": 1}
        assert summary.countries == {"TH": 1, "JP": 1}  # normalized to upper case
        assert summary.kev_added == [
            KevEntry(
                cve_id="CVE-2026-1", title="CVE-2026-1: Gateway RCE", due_date=date(2026, 10, 1)
            )
        ]

    def test_collector_failure_marks_day_incomplete(self) -> None:
        assert summarize(_report([_alert()], failed=True), TODAY).complete is False


class TestMergeHistory:
    def test_same_day_runs_are_summed(self) -> None:
        kev = KevEntry(cve_id="CVE-2026-1", title="t")
        first = _day(0, ransomware_claims=3, groups={"akira": 1}, kev_added=[kev])
        second = _day(0, ransomware_claims=2, groups={"akira": 1, "play": 1}, kev_added=[kev])
        second = second.model_copy(update={"complete": False})
        [merged] = merge_history([first], second)
        assert merged.ransomware_claims == 5
        assert merged.groups == {"akira": 2, "play": 1}
        assert merged.kev_added == [kev]  # deduplicated by CVE
        assert merged.complete is False

    def test_old_days_are_pruned_and_result_is_sorted(self) -> None:
        history = [_day(1), _day(5), _day(2)]
        merged = merge_history(history, _day(0), keep_days=3)
        assert [s.day for s in merged] == [
            TODAY - timedelta(days=2),
            TODAY - timedelta(days=1),
            TODAY,
        ]


class TestComputeTrends:
    def test_short_history_makes_no_comparison(self) -> None:
        history = [_day(2, ransomware_claims=4, groups={"akira": 4}), _day(0, ransomware_claims=1)]
        trends = compute_trends(history, TODAY, watch_countries=[])
        assert trends.history_days == 3
        assert trends.has_previous is False
        assert trends.ransomware_claims.current == 5
        assert trends.ransomware_claims.previous is None
        assert trends.top_groups[0].previous is None
        assert trends.new_groups == []  # everything would look "new" without a baseline

    def test_week_over_week_deltas_and_new_groups(self) -> None:
        history = [
            _day(13, ransomware_claims=4, groups={"akira": 4}),
            _day(8, ransomware_claims=3, groups={"akira": 3}),
            _day(3, ransomware_claims=5, groups={"akira": 3, "newgang": 2}),
        ]
        trends = compute_trends(history, TODAY, watch_countries=[])
        assert trends.has_previous is True
        assert (trends.ransomware_claims.current, trends.ransomware_claims.previous) == (5, 7)
        top = {d.name: (d.current, d.previous) for d in trends.top_groups}
        assert top == {"akira": (3, 7), "newgang": (2, 0)}
        assert trends.new_groups == ["newgang"]

    def test_new_group_detection_ignores_case(self) -> None:
        history = [_day(10, groups={"Akira": 1}), _day(1, groups={"akira": 1})]
        assert compute_trends(history, TODAY, watch_countries=[]).new_groups == []

    def test_watch_countries_match_case_insensitively(self) -> None:
        history = [_day(0, countries={"TH": 2, "JP": 1, "US": 5})]
        trends = compute_trends(history, TODAY, watch_countries=["th", " JP "])
        assert trends.watch_countries.current == 3
        assert [(d.name, d.current) for d in trends.watch_country_breakdown] == [
            ("TH", 2),
            ("JP", 1),
        ]

    def test_kev_due_soon_covers_next_seven_days_only(self) -> None:
        def kev(cve: str, due_offset: int) -> KevEntry:
            return KevEntry(cve_id=cve, title=cve, due_date=TODAY + timedelta(days=due_offset))

        history = [
            _day(20, kev_added=[kev("CVE-late", 8), kev("CVE-past", -1)]),
            _day(3, kev_added=[kev("CVE-edge", 7), kev("CVE-today", 0)]),
            _day(0, kev_added=[kev("CVE-today", 0)]),  # same CVE again: listed once
        ]
        trends = compute_trends(history, TODAY, watch_countries=[])
        assert [e.cve_id for e in trends.kev_due_soon] == ["CVE-today", "CVE-edge"]

    def test_incomplete_days_in_window_are_counted(self) -> None:
        history = [_day(0).model_copy(update={"complete": False}), _day(9)]
        history[1] = history[1].model_copy(update={"complete": False})  # outside window
        assert compute_trends(history, TODAY, watch_countries=[]).incomplete_days == 1

    def test_ties_are_ordered_by_name_for_stable_output(self) -> None:
        history = [_day(0, sectors={"Tech": 2, "Energy": 2, "Retail": 3})]
        trends = compute_trends(history, TODAY, watch_countries=[])
        assert [d.name for d in trends.top_sectors] == ["Retail", "Energy", "Tech"]
