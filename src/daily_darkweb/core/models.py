"""Domain models. Pure: no I/O, no network, no AI."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator


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

    @field_validator("fetched_at", "published_at")
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


class Report(BaseModel):
    generated_at: datetime
    collector_results: list[CollectResult]
    alerts: list[Alert]
    observations: list[Alert]

    @property
    def has_failures(self) -> bool:
        return any(r.status is CollectionStatus.FAILED for r in self.collector_results)
