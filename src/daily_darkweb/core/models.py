"""Domain models. Pure: no I/O, no network, no AI."""

from __future__ import annotations

import re
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MatchField(StrEnum):
    DOMAIN = "domain"
    ORG = "org"
    KEYWORD = "keyword"
    SECTOR = "sector"
    COUNTRY = "country"


class CollectionStatus(StrEnum):
    OK = "ok"
    FAILED = "failed"


def _ensure_aware(value: datetime) -> datetime:
    # Sources sometimes emit naive timestamps; treat them as UTC rather than guessing.
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


class RawItem(BaseModel):
    """One normalized signal from any collector. Content fields are untrusted data."""

    model_config = ConfigDict(frozen=True)

    source: str
    external_id: str
    title: str
    body: str = ""
    fetched_at: datetime
    published_at: datetime | None = None
    actor: str | None = None
    sector: str | None = None
    country: str | None = None
    victim_domain: str | None = None
    reference_url: str | None = None
    due_date: datetime | None = None  # remediation deadline, when the source provides one

    @field_validator("fetched_at", "published_at", "due_date")
    @classmethod
    def _aware(cls, v: datetime | None) -> datetime | None:
        return None if v is None else _ensure_aware(v)


class Watchlist(BaseModel):
    org_names: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    sectors: list[str] = Field(default_factory=list)
    countries: list[str] = Field(default_factory=list)


class Match(BaseModel):
    model_config = ConfigDict(frozen=True)

    field: MatchField
    watch_value: str
    matched_text: str


class Alert(BaseModel):
    item: RawItem
    matches: list[Match]
    score: int
    severity: Severity


class CollectResult(BaseModel):
    """Fail-closed collector outcome: FAILED means 'could not determine', never 'all clear'."""

    source: str
    status: CollectionStatus
    items: list[RawItem] = Field(default_factory=list)
    error: str | None = None


class KevEntry(BaseModel):
    """A CISA KEV addition as remembered in history (for upcoming-deadline tracking)."""

    cve_id: str
    title: str
    due_date: date | None = None


class DailySummary(BaseModel):
    """Counts of the *new* signals reported on one UTC day. Seen-state dedup means several
    runs on the same day never double-count, so their summaries can simply be added."""

    day: date
    complete: bool = True  # False when any collector failed on this day
    ransomware_claims: int = 0
    groups: dict[str, int] = Field(default_factory=dict)
    sectors: dict[str, int] = Field(default_factory=dict)
    countries: dict[str, int] = Field(default_factory=dict)
    kev_added: list[KevEntry] = Field(default_factory=list)


class CountDelta(BaseModel):
    name: str
    current: int
    previous: int | None = None  # None until history covers the previous window


class Trends(BaseModel):
    """Current window vs the window before it. `previous` values are None while history
    is still shorter than two windows — comparisons are never made against missing data."""

    window_days: int
    history_days: int
    incomplete_days: int  # days in the current window with a collector failure
    ransomware_claims: CountDelta
    top_groups: list[CountDelta]
    new_groups: list[str]
    top_sectors: list[CountDelta]
    top_countries: list[CountDelta]
    watch_countries: CountDelta
    watch_country_breakdown: list[CountDelta]
    kev_added: CountDelta
    kev_due_soon: list[KevEntry]

    @property
    def has_previous(self) -> bool:
        return self.ransomware_claims.previous is not None


_NoteLine = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=400)]
_URL_RE = re.compile(r"(?i)\b(?:[a-z][a-z0-9+.-]*://|www\.)")


class AnalystNotes(BaseModel):
    """Optional AI-written commentary, produced outside the deterministic core.

    Treated as untrusted text: strict schema, bounded sizes, rendered escaped and labelled
    "AI generated". Links are refused outright so injected scraped content can never turn
    the notes into a phishing vector — references belong to the deterministic digest.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    headline: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
    points: list[_NoteLine] = Field(min_length=1, max_length=6)
    actions: list[_NoteLine] = Field(default_factory=list, max_length=5)
    caveats: list[_NoteLine] = Field(default_factory=list, max_length=3)

    @model_validator(mode="after")
    def _no_links(self) -> AnalystNotes:
        for text in (self.headline, *self.points, *self.actions, *self.caveats):
            if _URL_RE.search(text):
                raise ValueError("links are not allowed in analyst notes")
        return self


class Report(BaseModel):
    generated_at: datetime
    collector_results: list[CollectResult]
    alerts: list[Alert]
    observations: list[Alert]
    trends: Trends | None = None
    analyst_notes: AnalystNotes | None = None
    # Why notes that were requested are missing; rendered instead of the notes box.
    analyst_notes_unavailable: str | None = None

    @property
    def has_failures(self) -> bool:
        return any(r.status is CollectionStatus.FAILED for r in self.collector_results)
