from __future__ import annotations

from datetime import UTC, datetime, timedelta

from daily_darkweb.core.models import Match, MatchField, Severity
from daily_darkweb.core.scoring import UNMATCHED_SCORE_CAP, score_item
from tests.conftest import make_item


def _match(field: MatchField) -> Match:
    return Match(field=field, watch_value="x", matched_text="x")


def test_domain_match_recent_is_critical(now: datetime) -> None:
    score, severity = score_item(make_item(), [_match(MatchField.DOMAIN)], now)
    assert score == 95  # 40 base + 40 domain + 15 recency
    assert severity is Severity.CRITICAL


def test_unmatched_capped_below_alert_grade(now: datetime) -> None:
    score, severity = score_item(make_item(), [], now)
    assert score <= UNMATCHED_SCORE_CAP
    assert severity in (Severity.MEDIUM, Severity.LOW, Severity.INFO)


def test_duplicate_field_counted_once(now: datetime) -> None:
    matches = [_match(MatchField.KEYWORD), _match(MatchField.KEYWORD)]
    score, _ = score_item(make_item(), matches, now)
    assert score == 40 + 20 + 15


def test_score_capped_at_100(now: datetime) -> None:
    matches = [_match(f) for f in MatchField]
    score, severity = score_item(make_item(), matches, now)
    assert score == 100
    assert severity is Severity.CRITICAL


def test_recency_decay(now: datetime) -> None:
    old = make_item(published_at=now - timedelta(days=40))
    fresh = make_item(published_at=now)
    match = [_match(MatchField.ORG)]
    assert score_item(fresh, match, now)[0] > score_item(old, match, now)[0]


def test_deterministic(now: datetime) -> None:
    item = make_item()
    match = [_match(MatchField.DOMAIN)]
    assert score_item(item, match, now) == score_item(item, match, now)


def test_naive_datetime_treated_as_utc() -> None:
    item = make_item(published_at=datetime(2026, 7, 20, 11, 0))
    assert item.published_at is not None
    assert item.published_at.tzinfo is UTC
