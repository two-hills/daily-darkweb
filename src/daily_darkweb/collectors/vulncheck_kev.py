"""VulnCheck KEV adapter: exploited CVEs beyond CISA KEV (free community token).

VulnCheck tracks vulnerabilities with public evidence of in-the-wild exploitation; its
catalogue is a superset of CISA KEV and usually earlier. Only entries CISA has *not* listed
are emitted — the CISA KEV collector reports those, with their federal deadline — so this
source is the early-warning layer: exploited, but not yet in CISA KEV.

Entries VulnCheck added on/after the caller-supplied `since` date are fetched newest first;
the CLI widens that window to cover gaps between runs, and the seen-state filter handles
repeats. Auth is a Bearer token. Cloud runs send none: the environment's API credentials
make the network proxy add it, so it never enters the session. Local runs pass
VULNCHECK_API_TOKEN, sent to this source's requests only. VulnCheck asks for attribution;
the digest credits it.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime
from urllib.parse import urlencode

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from daily_darkweb.collectors.base import fetch_json
from daily_darkweb.core.models import CollectionStatus, CollectResult, RawItem
from daily_darkweb.core.sanitize import scrub

logger = structlog.get_logger()

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_PAGE_SIZE = 200
_MAX_PAGES = 6  # the API serves at most six pages per query


class _VulnCheckRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    cve: list[str] | None = None
    vendor: str | None = Field(alias="vendorProject", default=None)
    product: str | None = None
    name: str | None = Field(alias="vulnerabilityName", default=None)
    short_description: str | None = Field(alias="shortDescription", default=None)
    required_action: str | None = None
    known_ransomware: str | None = Field(alias="knownRansomwareCampaignUse", default=None)
    cwes: list[str] | None = None
    date_added: datetime
    cisa_date_added: datetime | None = None
    due_date: datetime | None = Field(alias="dueDate", default=None)
    reported_exploitation: list[object] | None = Field(
        alias="vulncheck_reported_exploitation", default=None
    )
    exploits: list[object] | None = Field(alias="vulncheck_xdb", default=None)
    canaries: bool = Field(alias="reported_exploited_by_vulncheck_canaries", default=False)


class VulnCheckKevCollector:
    name = "vulncheck_kev"

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        since: date,
        base_url: str = "https://api.vulncheck.com/v3",
        timeout_seconds: float = 30.0,
        max_items: int = 50,
        api_token: str | None = None,
    ) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")
        self._since = since
        self._timeout = timeout_seconds
        self._max_items = max_items
        self._headers = {"Authorization": f"Bearer {api_token}"} if api_token else None

    async def collect(self) -> CollectResult:
        picked: list[tuple[str, _VulnCheckRecord]] = []
        rows_seen = skipped = 0
        page = 1
        while True:
            try:
                payload = await self._page(page)
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status in (401, 403):
                    return self._failed(
                        f"API token missing or rejected (HTTP {status}): check the Bearer "
                        "credential (cloud: environment API credentials; local: "
                        "VULNCHECK_API_TOKEN). Tokens unused for 30 days expire."
                    )
                return self._failed(f"{type(exc).__name__}: {exc}")
            except Exception as exc:
                return self._failed(f"{type(exc).__name__}: {exc}")

            rows = payload.get("data") if isinstance(payload, dict) else None
            if not isinstance(rows, list):
                return self._failed("unexpected payload shape: expected an object with a data list")
            rows_seen += len(rows)
            for raw in rows:
                try:
                    record = _VulnCheckRecord.model_validate(raw)
                except ValidationError:
                    skipped += 1
                    continue
                cve_id = next((c for c in record.cve or [] if _CVE_ID.match(c)), None)
                if cve_id is None:
                    skipped += 1
                    continue
                # CISA-listed entries belong to the CISA KEV collector; out-of-window rows
                # are dropped defensively in case the API ignores the date filter.
                if record.cisa_date_added is not None or _day(record.date_added) < self._since:
                    continue
                picked.append((cve_id, record))

            meta = payload.get("_meta") if isinstance(payload, dict) else None
            total_pages = meta.get("total_pages") if isinstance(meta, dict) else None
            done = not isinstance(total_pages, int) or page >= min(total_pages, _MAX_PAGES)
            if done or len(picked) >= self._max_items:
                break
            page += 1

        if rows_seen and skipped == rows_seen:
            return self._failed(f"all {skipped} records failed validation")
        if skipped:
            logger.warning("records_skipped", source=self.name, skipped=skipped)
        # Newest first before truncating, so a wide catch-up window drops the oldest.
        newest: dict[str, _VulnCheckRecord] = {}
        for cve_id, record in sorted(picked, key=lambda pair: pair[1].date_added, reverse=True):
            newest.setdefault(cve_id, record)
        fetched_at = datetime.now(UTC)
        items = [
            self._to_item(cve_id, record, fetched_at)
            for cve_id, record in list(newest.items())[: self._max_items]
        ]
        return CollectResult(source=self.name, status=CollectionStatus.OK, items=items)

    async def _page(self, page: int) -> object:
        query = urlencode(
            {
                "pubStartDate": self._since.isoformat(),
                "sort": "date_added",
                "order": "desc",
                "limit": _PAGE_SIZE,
                "page": page,
            }
        )
        url = f"{self._base_url}/index/vulncheck-kev?{query}"
        return await fetch_json(self._client, url, self._timeout, headers=self._headers)

    def _failed(self, error: str) -> CollectResult:
        logger.warning("collect_failed", source=self.name, error=error)
        return CollectResult(source=self.name, status=CollectionStatus.FAILED, error=error)

    def _to_item(self, cve_id: str, record: _VulnCheckRecord, fetched_at: datetime) -> RawItem:
        reports = len(record.reported_exploitation or [])
        evidence = [f"{reports} public report{'' if reports == 1 else 's'}"] if reports else []
        if record.canaries:
            evidence.append("VulnCheck's own sensors (canaries)")
        exploits = len(record.exploits or [])
        vendor, product = _clean(record.vendor), _clean(record.product)
        action = _clean(record.required_action)
        body_parts = [
            f"Vendor: {vendor or 'unknown'} | Product: {product or 'unknown'}",
            _clean(record.short_description),
            f"Required action: {action}" if action else "",
            (
                "Known use in ransomware campaigns."
                if (record.known_ransomware or "").strip().lower() == "known"
                else ""
            ),
            f"Exploitation evidence: {', '.join(evidence)}" if evidence else "",
            f"Public exploit code: {exploits} known" if exploits else "",
            f"CWE: {', '.join(record.cwes)}" if record.cwes else "",
            "Not yet in CISA KEV.",
        ]
        return RawItem(
            source=self.name,
            external_id=cve_id,
            title=scrub(f"{cve_id}: {_clean(record.name) or 'exploited vulnerability'}"),
            body=scrub("\n".join(part for part in body_parts if part.strip())),
            fetched_at=fetched_at,
            published_at=record.date_added,
            due_date=record.due_date,
            reference_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        )


def _clean(value: str | None) -> str:
    """Collapse the stray whitespace some records carry (e.g. a blank vendor prefix)."""
    return " ".join((value or "").split())


def _day(value: datetime) -> date:
    return value.astimezone(UTC).date() if value.tzinfo else value.date()
