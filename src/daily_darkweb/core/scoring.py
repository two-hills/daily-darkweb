"""Deterministic severity scoring. `now` is a parameter so results are reproducible."""

from __future__ import annotations

from datetime import datetime

from daily_darkweb.core.models import Match, MatchField, RawItem, Severity

SOURCE_BASE: dict[str, int] = {
    "ransomware_live": 40,
    # KEV entries are confirmed exploited-in-the-wild, the strongest single signal we ingest.
    "cisa_kev": 45,
}
DEFAULT_SOURCE_BASE = 30

MATCH_WEIGHTS: dict[MatchField, int] = {
    MatchField.DOMAIN: 40,
    MatchField.ORG: 35,
    MatchField.KEYWORD: 20,
    MatchField.SECTOR: 8,
    MatchField.COUNTRY: 4,
}

# Signals with no watchlist hit stay background landscape, never alert-grade.
UNMATCHED_SCORE_CAP = 45

_SEVERITY_THRESHOLDS: list[tuple[int, Severity]] = [
    (85, Severity.CRITICAL),
    (65, Severity.HIGH),
    (45, Severity.MEDIUM),
    (25, Severity.LOW),
]


def recency_boost(item: RawItem, now: datetime) -> int:
    reference = item.published_at or item.fetched_at
    age_days = (now - reference).total_seconds() / 86400
    if age_days <= 1:
        return 15
    if age_days <= 7:
        return 8
    if age_days <= 30:
        return 3
    return 0


def score_item(item: RawItem, matches: list[Match], now: datetime) -> tuple[int, Severity]:
    base = SOURCE_BASE.get(item.source, DEFAULT_SOURCE_BASE)
    # One weight per distinct field: five keyword hits shouldn't outrank a domain hit.
    match_score = sum(MATCH_WEIGHTS[field] for field in {m.field for m in matches})
    score = base + match_score + recency_boost(item, now)
    if not matches:
        score = min(score, UNMATCHED_SCORE_CAP)
    score = min(score, 100)
    return score, _severity(score)


def _severity(score: int) -> Severity:
    for threshold, severity in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return Severity.INFO
