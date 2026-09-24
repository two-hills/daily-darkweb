"""History and trend statistics. Pure and deterministic: no I/O, no network, no AI.

History keeps one compact DailySummary per UTC run day of the *new* signals reported.
Trends compare the latest window with the one before it, and only once history actually
spans both windows, so a young history never fakes a week-over-week change.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import date, timedelta

from daily_darkweb.core.models import CountDelta, DailySummary, KevEntry, Report, Trends

RANSOMWARE_SOURCE = "ransomware_live"
KEV_SOURCE = "cisa_kev"
WINDOW_DAYS = 7
HISTORY_KEEP_DAYS = 60
DUE_SOON_DAYS = 7
TOP_N = 5


def summarize(report: Report, day: date) -> DailySummary:
    """Summarize a run's new signals (alerts and observations alike) under `day`."""
    groups: Counter[str] = Counter()
    sectors: Counter[str] = Counter()
    countries: Counter[str] = Counter()
    claims = 0
    kev: list[KevEntry] = []
    for alert in [*report.alerts, *report.observations]:
        item = alert.item
        if item.source == RANSOMWARE_SOURCE:
            claims += 1
            if item.actor:
                groups[item.actor] += 1
            if item.sector:
                sectors[item.sector] += 1
            if item.country:
                countries[item.country.strip().upper()] += 1
        elif item.source == KEV_SOURCE:
            due = item.due_date.date() if item.due_date else None
            kev.append(KevEntry(cve_id=item.external_id, title=item.title, due_date=due))
    return DailySummary(
        day=day,
        complete=not report.has_failures,
        ransomware_claims=claims,
        groups=dict(groups),
        sectors=dict(sectors),
        countries=dict(countries),
        kev_added=kev,
    )


def merge_history(
    history: Iterable[DailySummary],
    summary: DailySummary,
    keep_days: int = HISTORY_KEEP_DAYS,
) -> list[DailySummary]:
    """Add `summary` to history (summing into an existing same-day entry), keep only the
    newest `keep_days` days, and return it sorted oldest first."""
    by_day = {s.day: s for s in history}
    existing = by_day.get(summary.day)
    by_day[summary.day] = _add(existing, summary) if existing else summary
    cutoff = max(by_day) - timedelta(days=keep_days - 1)
    return [by_day[d] for d in sorted(by_day) if d >= cutoff]


def compute_trends(
    history: list[DailySummary],
    today: date,
    watch_countries: Iterable[str],
    window_days: int = WINDOW_DAYS,
) -> Trends:
    current_start = today - timedelta(days=window_days - 1)
    previous_start = current_start - timedelta(days=window_days)
    current = [s for s in history if current_start <= s.day <= today]
    previous = [s for s in history if previous_start <= s.day < current_start]
    oldest = min((s.day for s in history), default=today)
    has_previous = oldest <= previous_start

    def delta(name: str, cur: int, prev: int) -> CountDelta:
        return CountDelta(name=name, current=cur, previous=prev if has_previous else None)

    cur_groups, prev_groups = _total(s.groups for s in current), _total(s.groups for s in previous)
    cur_sectors = _total(s.sectors for s in current)
    prev_sectors = _total(s.sectors for s in previous)
    cur_countries = _total(s.countries for s in current)
    prev_countries = _total(s.countries for s in previous)

    earlier_groups = {g.lower() for s in history if s.day < current_start for g in s.groups}
    new_groups = (
        sorted(g for g in cur_groups if g.lower() not in earlier_groups) if has_previous else []
    )

    watch = {c.strip().upper() for c in watch_countries}
    cur_watch = Counter({c: n for c, n in cur_countries.items() if c in watch})
    prev_watch = Counter({c: n for c, n in prev_countries.items() if c in watch})

    return Trends(
        window_days=window_days,
        history_days=(today - oldest).days + 1 if history else 0,
        incomplete_days=sum(1 for s in current if not s.complete),
        ransomware_claims=delta(
            "ransomware claims",
            sum(s.ransomware_claims for s in current),
            sum(s.ransomware_claims for s in previous),
        ),
        top_groups=[delta(n, c, prev_groups[n]) for n, c in _top(cur_groups)],
        new_groups=new_groups,
        top_sectors=[delta(n, c, prev_sectors[n]) for n, c in _top(cur_sectors)],
        top_countries=[delta(n, c, prev_countries[n]) for n, c in _top(cur_countries)],
        watch_countries=delta(
            "watchlist countries", sum(cur_watch.values()), sum(prev_watch.values())
        ),
        watch_country_breakdown=[delta(n, c, prev_watch[n]) for n, c in _top(cur_watch)],
        kev_added=delta(
            "CISA KEV additions",
            sum(len(s.kev_added) for s in current),
            sum(len(s.kev_added) for s in previous),
        ),
        kev_due_soon=_due_soon(history, today),
    )


def _add(a: DailySummary, b: DailySummary) -> DailySummary:
    return DailySummary(
        day=a.day,
        complete=a.complete and b.complete,
        ransomware_claims=a.ransomware_claims + b.ransomware_claims,
        groups=dict(Counter(a.groups) + Counter(b.groups)),
        sectors=dict(Counter(a.sectors) + Counter(b.sectors)),
        countries=dict(Counter(a.countries) + Counter(b.countries)),
        kev_added=_unique_kev([*a.kev_added, *b.kev_added]),
    )


def _total(counts: Iterable[Mapping[str, int]]) -> Counter[str]:
    total: Counter[str] = Counter()
    for c in counts:
        total.update(c)
    return total


def _top(counter: Counter[str], n: int = TOP_N) -> list[tuple[str, int]]:
    # Explicit tie-break on name: output must not depend on history iteration order.
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]


def _unique_kev(entries: Iterable[KevEntry]) -> list[KevEntry]:
    seen: set[str] = set()
    unique: list[KevEntry] = []
    for entry in entries:
        if entry.cve_id not in seen:
            seen.add(entry.cve_id)
            unique.append(entry)
    return unique


def _due_soon(history: list[DailySummary], today: date) -> list[KevEntry]:
    horizon = today + timedelta(days=DUE_SOON_DAYS)
    due = [
        e
        for e in _unique_kev(e for s in history for e in s.kev_added)
        if e.due_date is not None and today <= e.due_date <= horizon
    ]
    return sorted(due, key=lambda e: (e.due_date or today, e.cve_id))
