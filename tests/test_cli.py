from __future__ import annotations

import argparse
import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
import respx
from pydantic import ValidationError

from daily_darkweb.core.models import (
    Alert,
    CollectionStatus,
    CollectResult,
    DailySummary,
    Report,
    Severity,
)
from daily_darkweb.interface.cli import (
    _effective_recent_days,
    _load_state,
    _run,
    _save_state,
    _State,
)
from tests.conftest import make_item

NOW = datetime(2026, 9, 23, 6, 0, tzinfo=UTC)
FEED_URL = "https://kev.test.invalid/feed.json"

# The real incident this guards against: pipeline last ran 2026-08-18, next run
# 2026-09-23; entries added in between fell outside the fixed 30-day window.
GAP_VULN = {
    "cveID": "CVE-2026-73570",
    "vendorProject": "Zimbra",
    "product": "Collaboration",
    "vulnerabilityName": "Zimbra Collaboration SSRF Vulnerability",
    "dateAdded": "2026-08-19",
    "shortDescription": "Zimbra Collaboration contains an SSRF vulnerability.",
    "requiredAction": "Apply updates per vendor instructions.",
}


def _ok_report(alerts: list[Alert] | None = None) -> Report:
    return Report(
        generated_at=NOW,
        collector_results=[CollectResult(source="cisa_kev", status=CollectionStatus.OK)],
        alerts=alerts or [],
        observations=[],
    )


def _failed_report() -> Report:
    return Report(
        generated_at=NOW,
        collector_results=[
            CollectResult(source="cisa_kev", status=CollectionStatus.FAILED, error="boom")
        ],
        alerts=[],
        observations=[],
    )


class TestEffectiveRecentDays:
    def test_no_previous_run_uses_configured_floor(self) -> None:
        assert _effective_recent_days(30, None, NOW) == 30

    def test_fresh_run_uses_configured_floor(self) -> None:
        assert _effective_recent_days(30, NOW - timedelta(days=1), NOW) == 30

    def test_gap_beyond_floor_widens_window(self) -> None:
        assert _effective_recent_days(30, NOW - timedelta(days=36), NOW) == 36

    def test_partial_day_rounds_up(self) -> None:
        assert _effective_recent_days(30, NOW - timedelta(days=35, hours=1), NOW) == 36

    def test_gap_growth_is_capped(self) -> None:
        assert _effective_recent_days(30, NOW - timedelta(days=800), NOW) == 365

    def test_configured_floor_above_cap_is_honored(self) -> None:
        assert _effective_recent_days(400, NOW - timedelta(days=800), NOW) == 400

    def test_future_timestamp_falls_back_to_floor(self) -> None:
        assert _effective_recent_days(30, NOW + timedelta(days=2), NOW) == 30


class TestStateFile:
    def test_missing_file_yields_empty_state(self, tmp_path: Path) -> None:
        state = _load_state(tmp_path / "seen.json")
        assert state.seen == []
        assert state.last_success is None

    def test_legacy_seen_only_format_still_loads(self, tmp_path: Path) -> None:
        path = tmp_path / "seen.json"
        path.write_text(json.dumps({"seen": ["k1", "k2"]}), encoding="utf-8")
        state = _load_state(path)
        assert state.seen == ["k1", "k2"]
        assert state.last_success is None

    def test_corrupt_timestamp_fails_loudly(self, tmp_path: Path) -> None:
        path = tmp_path / "seen.json"
        path.write_text(json.dumps({"seen": [], "last_success": "not-a-date"}), encoding="utf-8")
        with pytest.raises(ValidationError):
            _load_state(path)

    def test_clean_run_records_last_success_and_merges_seen(self, tmp_path: Path) -> None:
        path = tmp_path / "seen.json"
        alert = Alert(item=make_item(), matches=[], score=0, severity=Severity.INFO)
        _save_state(path, _State(seen=["old-key"]), _ok_report(alerts=[alert]), NOW)
        state = _load_state(path)
        assert state.last_success == NOW
        assert len(state.seen) == 2
        assert state.seen[0] == "old-key"

    def test_failed_run_preserves_previous_last_success(self, tmp_path: Path) -> None:
        path = tmp_path / "seen.json"
        earlier = NOW - timedelta(days=5)
        _save_state(path, _State(last_success=earlier), _failed_report(), NOW)
        assert _load_state(path).last_success == earlier


def _write_config(config_dir: Path) -> None:
    config_dir.mkdir(parents=True)
    (config_dir / "sources.yaml").write_text(
        "ransomware_live:\n"
        "  enabled: false\n"
        "cisa_kev:\n"
        "  enabled: true\n"
        f'  feed_url: "{FEED_URL}"\n'
        "  timeout_seconds: 1.0\n"
        "  recent_days: 30\n"
        "  max_items: 200\n",
        encoding="utf-8",
    )
    (config_dir / "watchlist.yaml").write_text("keywords: []\n", encoding="utf-8")


def _make_args(tmp_path: Path) -> argparse.Namespace:
    return argparse.Namespace(
        config_dir=str(tmp_path / "config"),
        state=str(tmp_path / "state" / "seen.json"),
        no_state=False,
        format="json",
        html_out=None,
        email=False,
        report_out=None,
        from_report=None,
        notes=None,
    )


def _write_state(tmp_path: Path, state: _State) -> Path:
    path = tmp_path / "state" / "seen.json"
    path.parent.mkdir(parents=True)
    path.write_text(state.model_dump_json(), encoding="utf-8")
    return path


@respx.mock
async def test_sparse_run_gap_recovers_missed_entries(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """gap (36d) > recent_days (30d): the entry added inside the gap must be reported."""
    _write_config(tmp_path / "config")
    state_path = _write_state(
        tmp_path, _State(last_success=datetime(2026, 8, 18, 5, 0, tzinfo=UTC))
    )
    respx.get(FEED_URL).respond(json={"vulnerabilities": [GAP_VULN]})

    exit_code = await _run(_make_args(tmp_path), now=NOW)

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    reported_ids = [obs["item"]["external_id"] for obs in report["observations"]]
    assert reported_ids == ["CVE-2026-73570"]
    assert exit_code == 0
    assert "widening lookback" in captured.err

    saved = _load_state(state_path)
    assert saved.last_success == NOW
    assert len(saved.seen) == 1


@respx.mock
async def test_recent_last_run_keeps_configured_window(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """No gap: an entry older than recent_days stays outside the window (seen-state
    already covered it on earlier runs)."""
    _write_config(tmp_path / "config")
    _write_state(tmp_path, _State(last_success=NOW - timedelta(days=1)))
    respx.get(FEED_URL).respond(json={"vulnerabilities": [GAP_VULN]})

    exit_code = await _run(_make_args(tmp_path), now=NOW)

    report = json.loads(capsys.readouterr().out)
    assert report["observations"] == []
    assert exit_code == 0


@respx.mock
async def test_failed_collection_does_not_advance_last_success(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Fail closed: a broken run must not mark its window as covered."""
    _write_config(tmp_path / "config")
    earlier = datetime(2026, 8, 18, 5, 0, tzinfo=UTC)
    state_path = _write_state(tmp_path, _State(seen=["old-key"], last_success=earlier))
    respx.get(FEED_URL).respond(status_code=404)

    exit_code = await _run(_make_args(tmp_path), now=NOW)

    assert exit_code == 3
    saved = _load_state(state_path)
    assert saved.last_success == earlier
    assert saved.seen == ["old-key"]
    capsys.readouterr()


class TestHistoryState:
    def test_state_without_history_loads_with_empty_history(self, tmp_path: Path) -> None:
        path = tmp_path / "seen.json"
        path.write_text(json.dumps({"seen": ["k"], "last_success": None}), encoding="utf-8")
        assert _load_state(path).history == []

    def test_save_without_new_history_keeps_previous(self, tmp_path: Path) -> None:
        path = tmp_path / "seen.json"
        old = [DailySummary(day=date(2026, 9, 20), ransomware_claims=3)]
        _save_state(path, _State(history=old), _ok_report(), NOW)
        assert _load_state(path).history == old


RECENT_VULN = {
    **GAP_VULN,
    "cveID": "CVE-2026-80001",
    "dateAdded": "2026-09-22",
    "dueDate": "2026-09-25",
}


@respx.mock
async def test_collect_run_saves_history_and_attaches_trends(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_config(tmp_path / "config")
    state_path = _write_state(tmp_path, _State(last_success=NOW - timedelta(days=1)))
    respx.get(FEED_URL).respond(json={"vulnerabilities": [RECENT_VULN]})

    exit_code = await _run(_make_args(tmp_path), now=NOW)

    report = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert report["trends"]["kev_added"]["current"] == 1
    assert report["trends"]["kev_due_soon"][0]["cve_id"] == "CVE-2026-80001"
    saved = _load_state(state_path)
    assert [s.day for s in saved.history] == [NOW.date()]
    assert saved.history[0].kev_added[0].cve_id == "CVE-2026-80001"


@respx.mock
async def test_notes_are_added_by_re_rendering_a_saved_report_offline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The Routine flow: collect once with --report-out, let the model write notes, then
    re-render with --from-report --notes. The re-render must not collect or touch state."""
    _write_config(tmp_path / "config")
    state_path = _write_state(tmp_path, _State(last_success=NOW - timedelta(days=1)))
    respx.get(FEED_URL).respond(json={"vulnerabilities": [RECENT_VULN]})
    report_path = tmp_path / "out" / "report.json"
    collect_args = _make_args(tmp_path)
    collect_args.report_out = str(report_path)
    assert await _run(collect_args, now=NOW) == 0
    capsys.readouterr()
    state_before = state_path.read_bytes()
    calls_before = respx.calls.call_count

    notes_path = tmp_path / "notes.json"
    notes_path.write_text(
        json.dumps({"headline": "Quiet day", "points": ["One new KEV entry."]}), encoding="utf-8"
    )
    render_args = _make_args(tmp_path)
    render_args.from_report = str(report_path)
    render_args.notes = str(notes_path)
    render_args.format = "md"
    render_args.html_out = str(tmp_path / "out" / "digest.html")
    exit_code = await _run(render_args, now=NOW + timedelta(hours=1))

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "## AI analyst notes (AI generated)" in out
    assert "**Quiet day**" in out
    assert "## Trends (last 7 days)" in out  # trends survive the JSON round trip
    assert "CVE-2026-80001" in out
    assert "badge-ai'>AI generated" in (tmp_path / "out" / "digest.html").read_text("utf-8")
    assert respx.calls.call_count == calls_before  # no network on re-render
    assert state_path.read_bytes() == state_before  # state untouched


async def test_invalid_notes_render_as_unavailable_and_keep_exit_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(_failed_report().model_dump_json(), encoding="utf-8")
    notes_path = tmp_path / "notes.json"
    notes_path.write_text(
        json.dumps({"headline": "h", "points": ["see https://evil.example/login"]}),
        encoding="utf-8",
    )
    args = _make_args(tmp_path)
    args.from_report = str(report_path)
    args.notes = str(notes_path)
    args.format = "md"

    exit_code = await _run(args, now=NOW)

    captured = capsys.readouterr()
    assert exit_code == 3  # the saved run's collector failure still fails closed
    assert "Unavailable for this run: notes failed validation." in captured.out
    assert "evil.example" not in captured.out
    assert "links are not allowed" in captured.err


async def test_missing_notes_file_is_reported_not_fatal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(_ok_report().model_dump_json(), encoding="utf-8")
    args = _make_args(tmp_path)
    args.from_report = str(report_path)
    args.notes = str(tmp_path / "absent.json")
    args.format = "md"

    exit_code = await _run(args, now=NOW)

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Unavailable for this run: notes file missing or unreadable." in captured.out
    assert "notes: cannot read" in captured.err
