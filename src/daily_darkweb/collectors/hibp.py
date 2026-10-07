"""Have I Been Pwned breach catalogue adapter (public endpoint, no API key).

Every entry is a data breach HIBP has loaded: who was breached, when, how many accounts,
which kinds of data. Metadata only — this adapter reads the public catalogue and never
searches for any email address or domain. Entries added on/after the caller-supplied
`since` date are emitted; the CLI widens that window to cover gaps between runs, and the
seen-state filter handles repeats. Spam lists, fabricated and retired entries are not
breaches of an organisation and are dropped.

HIBP's own description of each incident becomes the item's display-only `summary`: it
nearly always says "breach", which would otherwise trip that watchlist keyword on every
entry. Data from haveibeenpwned.com is licensed CC BY 4.0; the digest credits it.
"""

from __future__ import annotations

import html
import re
from datetime import UTC, date, datetime
from urllib.parse import quote

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from daily_darkweb.collectors.base import fetch_json
from daily_darkweb.core.models import CollectionStatus, CollectResult, RawItem
from daily_darkweb.core.sanitize import clip, scrub

logger = structlog.get_logger()

_SUMMARY_LIMIT = 500
_TAG = re.compile(r"<[^>]*>")
_SPACE_BEFORE_PUNCT = re.compile(r" ([.,;:!?)])")
# Country-code TLDs widely sold as generic names: they say nothing about the country.
_GENERIC_CCTLDS = frozenset(
    {
        "ac", "ai", "bz", "cc", "cd", "co", "cx", "eu", "fm", "gd", "gg", "gl", "io",
        "la", "ly", "me", "ms", "nu", "sc", "sh", "so", "su", "tk", "to", "tv", "vc", "ws",
    }
)  # fmt: skip
_CCTLD_TO_ISO = {"uk": "GB"}


class _BreachRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str = Field(alias="Name", min_length=1)
    title: str = Field(alias="Title", default="")
    domain: str | None = Field(alias="Domain", default=None)
    breach_date: str | None = Field(alias="BreachDate", default=None)
    added_date: datetime = Field(alias="AddedDate")
    pwn_count: int = Field(alias="PwnCount", default=0, ge=0)
    description: str | None = Field(alias="Description", default=None)
    data_classes: list[str] = Field(alias="DataClasses", default_factory=list)
    is_verified: bool = Field(alias="IsVerified", default=True)
    is_fabricated: bool = Field(alias="IsFabricated", default=False)
    is_sensitive: bool = Field(alias="IsSensitive", default=False)
    is_retired: bool = Field(alias="IsRetired", default=False)
    is_spam_list: bool = Field(alias="IsSpamList", default=False)
    is_malware: bool = Field(alias="IsMalware", default=False)
    is_stealer_log: bool = Field(alias="IsStealerLog", default=False)


class HibpCollector:
    name = "hibp"

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        since: date,
        base_url: str = "https://haveibeenpwned.com/api/v3",
        timeout_seconds: float = 30.0,
        max_items: int = 50,
    ) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")
        self._since = since
        self._timeout = timeout_seconds
        self._max_items = max_items

    async def collect(self) -> CollectResult:
        try:
            payload = await fetch_json(self._client, f"{self._base_url}/breaches", self._timeout)
        except Exception as exc:
            return self._failed(f"{type(exc).__name__}: {exc}")
        if not isinstance(payload, list):
            return self._failed("unexpected payload shape: expected a JSON list of breaches")

        fetched_at = datetime.now(UTC)
        in_window: list[_BreachRecord] = []
        skipped = 0
        for raw in payload:
            try:
                record = _BreachRecord.model_validate(raw)
            except ValidationError:
                skipped += 1
                continue
            if record.added_date.astimezone(UTC).date() < self._since:
                continue
            if record.is_spam_list or record.is_fabricated or record.is_retired:
                continue
            in_window.append(record)

        if payload and skipped == len(payload):
            return self._failed(f"all {skipped} records failed validation")
        if skipped:
            logger.warning("records_skipped", source=self.name, skipped=skipped)
        # Newest first before truncating, so a wide catch-up window drops the oldest.
        in_window.sort(key=lambda r: r.added_date, reverse=True)
        items = [self._to_item(r, fetched_at) for r in in_window[: self._max_items]]
        return CollectResult(source=self.name, status=CollectionStatus.OK, items=items)

    def _failed(self, error: str) -> CollectResult:
        logger.warning("collect_failed", source=self.name, error=error)
        return CollectResult(source=self.name, status=CollectionStatus.FAILED, error=error)

    def _to_item(self, record: _BreachRecord, fetched_at: datetime) -> RawItem:
        domain = _host(record.domain)
        country = _country_from_domain(domain)
        added = record.added_date.astimezone(UTC)
        details = []
        if record.data_classes:
            details.append(f"Exposed data: {', '.join(record.data_classes)}")
        incident = _day(record.breach_date)
        details.append(
            f"Incident date: {incident} · added to Have I Been Pwned: {added:%Y-%m-%d}"
            if incident
            else f"Added to Have I Been Pwned: {added:%Y-%m-%d}"
        )
        if country and domain:
            tld = domain.rsplit(".", 1)[-1]
            details.append(f"Country (inferred from the website's .{tld} domain): {country}")
        notes = [
            note
            for flag, note in (
                (not record.is_verified, "not verified by Have I Been Pwned"),
                (record.is_malware or record.is_stealer_log, "collected by infostealer malware"),
                (record.is_sensitive, "flagged sensitive by Have I Been Pwned"),
            )
            if flag
        ]
        if notes:
            details.append(f"Note: {'; '.join(notes)}")
        title = record.title.strip() or record.name
        return RawItem(
            source=self.name,
            external_id=record.name,
            title=scrub(f"{title}: {record.pwn_count:,} accounts exposed"),
            body=scrub("\n".join(details)),
            summary=clip(scrub(_plain_text(record.description)), _SUMMARY_LIMIT),
            fetched_at=fetched_at,
            published_at=added,
            country=country,
            victim_domain=domain,
            reference_url=f"https://haveibeenpwned.com/Breach/{quote(record.name, safe='')}",
        )


def _plain_text(value: str | None) -> str:
    """HIBP descriptions are HTML: drop the tags (and the links in them), decode entities."""
    if not value:
        return ""
    text = " ".join(html.unescape(_TAG.sub(" ", value)).split())
    return _SPACE_BEFORE_PUNCT.sub(r"\1", text)  # 'a link</a>.' must not read 'a link .'


def _host(value: str | None) -> str | None:
    if not value:
        return None
    host = re.sub(r"(?i)^[a-z][a-z0-9+.-]*:/*", "", value.strip()).split("/", 1)[0]
    return host.strip().lower() or None


def _country_from_domain(domain: str | None) -> str | None:
    """ISO code from a country-code TLD ('angelone.in' → 'IN', 'x.co.jp' → 'JP'). A hint
    only — the digest labels it as inferred — and None for generic-use ccTLDs."""
    if not domain or "." not in domain:
        return None
    tld = domain.rsplit(".", 1)[-1]
    if len(tld) != 2 or not tld.isalpha() or tld in _GENERIC_CCTLDS:
        return None
    return _CCTLD_TO_ISO.get(tld, tld.upper())


def _day(value: str | None) -> date | None:
    try:
        return date.fromisoformat(value[:10]) if value else None
    except ValueError:
        return None
