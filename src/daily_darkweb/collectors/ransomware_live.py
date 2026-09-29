"""ransomware.live adapter: clearnet aggregation of ransomware-group DLS activity.

Ingests victim-claim *metadata* only (who/when/sector/country) — never leaked payloads.
Scraped text is scrubbed of onion addresses, links and emails on the way in, and the
feed's leak-site fields (`claim_url`, `screenshot`, group `locations`) are never read.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime
from urllib.parse import quote

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from daily_darkweb.collectors.base import fetch_json
from daily_darkweb.core.models import (
    AttackTactic,
    AttackTechnique,
    CollectionStatus,
    CollectResult,
    GroupProfile,
    RawItem,
)
from daily_darkweb.core.sanitize import clip, scrub

logger = structlog.get_logger()

_DESCRIPTION_LIMIT = 600
_TECHNIQUE_DETAILS_LIMIT = 240
_TOOL_NAME_LIMIT = 80
_BR = re.compile(r"(?i)<br\s*/?>")
_TAG = re.compile(r"(?i)</?[a-z][^<>]*>")


class _VictimRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    victim: str
    group: str = ""
    activity: str | None = None
    country: str | None = None
    domain: str | None = None
    description: str | None = None
    attackdate: datetime | None = None
    discovered: datetime | None = None
    url: str | None = None


class _Technique(BaseModel):
    model_config = ConfigDict(extra="ignore")

    technique_id: str = ""
    technique_name: str = ""
    technique_details: str | None = ""


class _Tactic(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tactic_id: str = ""
    tactic_name: str = ""
    techniques: list[_Technique] = Field(default_factory=list)


class _GroupRecord(BaseModel):
    # `locations` (the group's .onion leak sites) is deliberately not modelled, so it
    # can never reach state, reports or email.
    model_config = ConfigDict(extra="ignore")

    name: str
    description: str | None = None
    added_date: str | None = None
    altname: str | None = None
    tools: list[dict[str, list[str]]] | None = None
    ttps: list[_Tactic] | None = None
    url: str | None = None


class RansomwareLiveCollector:
    name = "ransomware_live"

    def __init__(
        self,
        client: httpx.AsyncClient,
        base_url: str = "https://api.ransomware.live/v2",
        timeout_seconds: float = 15.0,
        max_items: int = 100,
    ) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._max_items = max_items

    async def collect(self) -> CollectResult:
        try:
            payload = await self._fetch_recent_victims()
        except Exception as exc:
            logger.warning("collect_failed", source=self.name, error=str(exc))
            return CollectResult(
                source=self.name,
                status=CollectionStatus.FAILED,
                error=f"{type(exc).__name__}: {exc}",
            )

        if not isinstance(payload, list):
            return CollectResult(
                source=self.name,
                status=CollectionStatus.FAILED,
                error="unexpected payload shape: expected a JSON list",
            )

        fetched_at = datetime.now(UTC)
        items: list[RawItem] = []
        skipped = 0
        for raw in payload[: self._max_items]:
            try:
                record = _VictimRecord.model_validate(raw)
            except ValidationError:
                skipped += 1
                continue
            items.append(self._to_item(record, fetched_at))

        if not items and skipped:
            return CollectResult(
                source=self.name,
                status=CollectionStatus.FAILED,
                error=f"all {skipped} records failed validation",
            )
        if skipped:
            logger.warning("records_skipped", source=self.name, skipped=skipped)
        return CollectResult(source=self.name, status=CollectionStatus.OK, items=items)

    async def group_profile(self, name: str) -> GroupProfile:
        """Fetch one group's profile. Raises on any failure; callers treat profiles as
        supplementary and must not turn a failed lookup into a collection failure."""
        url = f"{self._base_url}/group/{quote(name, safe='')}"
        payload = await fetch_json(self._client, url, self._timeout)
        return _to_profile(_GroupRecord.model_validate(payload))

    async def _fetch_recent_victims(self) -> object:
        return await fetch_json(self._client, f"{self._base_url}/recentvictims", self._timeout)

    def _to_item(self, record: _VictimRecord, fetched_at: datetime) -> RawItem:
        group = record.group or "unknown group"
        # The dedup key keeps using the raw URL so seen-state stays continuous.
        external_id = record.url or f"{record.victim}@{group}@{record.attackdate}"
        return RawItem(
            source=self.name,
            external_id=external_id,
            title=scrub(f"{record.victim} claimed by {group}"),
            body=scrub(_plain_text(_none_if_missing(record.description))),
            fetched_at=fetched_at,
            published_at=record.attackdate or record.discovered,
            actor=record.group or None,
            sector=_none_if_missing(record.activity),
            country=_none_if_missing(record.country),
            victim_domain=_host_only(_none_if_missing(record.domain)),
            reference_url=_clearnet_https(record.url),
        )


def _to_profile(record: _GroupRecord) -> GroupProfile:
    tools: dict[str, list[str]] = {}
    for block in record.tools or []:
        for category, names in block.items():
            cleaned = [clip(scrub(n), _TOOL_NAME_LIMIT) for n in names if n and n.strip()]
            if cleaned:
                tools.setdefault(scrub(category), []).extend(cleaned)
    tactics = [
        AttackTactic(
            tactic_id=t.tactic_id,
            name=t.tactic_name,
            techniques=[
                AttackTechnique(
                    technique_id=tech.technique_id,
                    name=scrub(tech.technique_name),
                    details=clip(
                        scrub(_plain_text(tech.technique_details)), _TECHNIQUE_DETAILS_LIMIT
                    ),
                )
                for tech in t.techniques
                if tech.technique_name
            ],
        )
        for t in record.ttps or []
        if t.tactic_name
    ]
    aliases = [a.strip() for a in (record.altname or "").split(",") if a.strip()]
    return GroupProfile(
        name=record.name,
        description=clip(scrub(_plain_text(record.description)), _DESCRIPTION_LIMIT),
        first_seen=_parse_day(record.added_date),
        aliases=[scrub(a) for a in aliases],
        tools=tools,
        tactics=tactics,
        reference_url=_clearnet_https(record.url),
    )


def _clearnet_https(url: str | None) -> str | None:
    """Only structured https links to clearnet pages are ever shown as references."""
    if not url or not url.lower().startswith("https://") or ".onion" in url.lower():
        return None
    return url


def _plain_text(value: str | None) -> str:
    """Source prose as one plain paragraph: `<BR>` and other tags, and the '>' quote
    markers some groups' posts carry, would otherwise show up literally in the digest."""
    if not value:
        return ""
    text = _TAG.sub(" ", _BR.sub("\n", value))
    lines = (line.strip().lstrip(">").strip() for line in text.splitlines())
    return " ".join(line for line in lines if line)


def _host_only(value: str | None) -> str | None:
    """'https://www.x.com/about' (or the malformed 'https:x.com') → 'www.x.com': the
    victim's website identifies it; a clickable link would not add anything."""
    if value is None:
        return None
    host = re.sub(r"(?i)^[a-z][a-z0-9+.-]*:/*", "", value.strip()).split("/", 1)[0].strip()
    return host or None


def _parse_day(value: str | None) -> date | None:
    try:
        return date.fromisoformat(value[:10]) if value else None
    except ValueError:
        return None


def _none_if_missing(value: str | None) -> str | None:
    if value is None:
        return None
    v = value.strip()
    return v if v and v.lower() not in {"not found", "n/a"} else None
