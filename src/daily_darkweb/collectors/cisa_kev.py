"""CISA Known Exploited Vulnerabilities adapter.

Every entry is a vulnerability with confirmed in-the-wild exploitation — the highest-value
free "fix this first" signal. Only recently added entries are emitted; the seen-state
filter handles repeats across runs.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from daily_darkweb.collectors.base import fetch_json
from daily_darkweb.core.models import CollectionStatus, CollectResult, RawItem

logger = structlog.get_logger()


class _KevRecord(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    cve_id: str = Field(alias="cveID")
    vendor: str = Field(alias="vendorProject", default="")
    product: str = ""
    name: str = Field(alias="vulnerabilityName", default="")
    date_added: date | None = Field(alias="dateAdded", default=None)
    due_date: date | None = Field(alias="dueDate", default=None)
    short_description: str = Field(alias="shortDescription", default="")
    required_action: str = Field(alias="requiredAction", default="")
    known_ransomware: str = Field(alias="knownRansomwareCampaignUse", default="Unknown")
    cwes: list[str] = Field(default_factory=list)


class CisaKevCollector:
    name = "cisa_kev"

    def __init__(
        self,
        client: httpx.AsyncClient,
        feed_url: str = (
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        ),
        timeout_seconds: float = 30.0,
        recent_days: int = 30,
        max_items: int = 200,
    ) -> None:
        self._client = client
        self._feed_url = feed_url
        self._timeout = timeout_seconds
        self._recent_days = recent_days
        self._max_items = max_items

    async def collect(self) -> CollectResult:
        try:
            payload = await fetch_json(self._client, self._feed_url, self._timeout)
        except Exception as exc:
            logger.warning("collect_failed", source=self.name, error=str(exc))
            return CollectResult(
                source=self.name,
                status=CollectionStatus.FAILED,
                error=f"{type(exc).__name__}: {exc}",
            )

        vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, dict) else None
        if not isinstance(vulnerabilities, list):
            return CollectResult(
                source=self.name,
                status=CollectionStatus.FAILED,
                error="unexpected payload shape: expected dict with 'vulnerabilities' list",
            )

        fetched_at = datetime.now(UTC)
        cutoff = fetched_at.date() - timedelta(days=self._recent_days)
        items: list[RawItem] = []
        skipped = 0
        for raw in vulnerabilities:
            try:
                record = _KevRecord.model_validate(raw)
            except ValidationError:
                skipped += 1
                continue
            if record.date_added is None or record.date_added < cutoff:
                continue
            items.append(self._to_item(record, fetched_at))
            if len(items) >= self._max_items:
                break

        if not items and skipped == len(vulnerabilities) and skipped:
            return CollectResult(
                source=self.name,
                status=CollectionStatus.FAILED,
                error=f"all {skipped} records failed validation",
            )
        if skipped:
            logger.warning("records_skipped", source=self.name, skipped=skipped)
        return CollectResult(source=self.name, status=CollectionStatus.OK, items=items)

    def _to_item(self, record: _KevRecord, fetched_at: datetime) -> RawItem:
        body_parts = [
            f"Vendor: {record.vendor} | Product: {record.product}",
            record.short_description,
            f"Required action: {record.required_action}",
        ]
        if record.known_ransomware.strip().lower() == "known":
            body_parts.append("Known use in ransomware campaigns.")
        if record.cwes:
            body_parts.append(f"CWE: {', '.join(record.cwes)}")
        return RawItem(
            source=self.name,
            external_id=record.cve_id,
            title=f"{record.cve_id}: {record.name or 'exploited vulnerability'}",
            body="\n".join(part for part in body_parts if part.strip()),
            fetched_at=fetched_at,
            published_at=_as_utc_datetime(record.date_added),
            due_date=_as_utc_datetime(record.due_date),
            reference_url=f"https://nvd.nist.gov/vuln/detail/{record.cve_id}",
        )


def _as_utc_datetime(value: date | None) -> datetime | None:
    if value is None:
        return None
    return datetime(value.year, value.month, value.day, tzinfo=UTC)
