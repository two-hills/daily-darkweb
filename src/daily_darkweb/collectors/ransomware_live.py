"""ransomware.live adapter: clearnet aggregation of ransomware-group DLS activity.

Ingests victim-claim *metadata* only (who/when/sector/country) — never leaked payloads.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, ValidationError

from daily_darkweb.collectors.base import fetch_json
from daily_darkweb.core.models import CollectionStatus, CollectResult, RawItem

logger = structlog.get_logger()


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

    async def _fetch_recent_victims(self) -> object:
        return await fetch_json(self._client, f"{self._base_url}/recentvictims", self._timeout)

    def _to_item(self, record: _VictimRecord, fetched_at: datetime) -> RawItem:
        group = record.group or "unknown group"
        external_id = record.url or f"{record.victim}@{group}@{record.attackdate}"
        return RawItem(
            source=self.name,
            external_id=external_id,
            title=f"{record.victim} claimed by {group}",
            body=record.description or "",
            fetched_at=fetched_at,
            published_at=record.attackdate or record.discovered,
            actor=record.group or None,
            sector=_none_if_missing(record.activity),
            country=_none_if_missing(record.country),
            victim_domain=_none_if_missing(record.domain),
            reference_url=record.url,
        )


def _none_if_missing(value: str | None) -> str | None:
    if value is None:
        return None
    v = value.strip()
    return v if v and v.lower() not in {"not found", "n/a"} else None
