"""ransomware.live adapter (API PRO): clearnet aggregation of ransomware-group DLS activity.

Ingests victim-claim *metadata* only (who/when/sector/country) — never leaked payloads.
Scraped text is scrubbed of onion addresses, links and emails on the way in. Fields that
point at leak sites or identify our account (`post_url`, `screenshot`, group `locations`,
`client`) are never modelled, so they cannot reach state, reports or email.

The PRO API wants an `X-API-KEY` header. Cloud runs send none: the session's network
proxy adds the key on the way out, so it never enters the session. Local runs pass it in
(RANSOMWARE_LIVE_API_KEY), and it is sent to this source's requests only.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime
from urllib.parse import quote

import httpx
import structlog
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, ValidationError

from daily_darkweb.collectors.base import fetch_json
from daily_darkweb.core.models import (
    AttackTactic,
    AttackTechnique,
    CollectionStatus,
    CollectResult,
    ExploitedCve,
    GroupProfile,
    InfostealerExposure,
    RawItem,
)
from daily_darkweb.core.sanitize import clip, scrub

logger = structlog.get_logger()

_DESCRIPTION_LIMIT = 600
_TECHNIQUE_DETAILS_LIMIT = 240
_TOOL_NAME_LIMIT = 80
_BR = re.compile(r"(?i)<br\s*/?>")
_TAG = re.compile(r"(?i)</?[a-z][^<>]*>")
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
# Victim permalinks end in base64("victim@group"). Seen-state keys come from the v2 API,
# which kept the base64 '=' padding; PRO drops it (see _dedup_id).
_PERMALINK_PREFIX = "https://www.ransomware.live/id/"


class _VictimRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    victim: str
    group: str = ""
    activity: str | None = None
    country: str | None = None
    website: str | None = None
    description: str | None = None
    attackdate: datetime | None = None
    discovered: datetime | None = None
    permalink: str | None = None
    # Enrichments are parsed leniently: a malformed one is dropped, never the victim.
    press: object = None
    infostealer: object = None


class _Infostealer(BaseModel):
    model_config = ConfigDict(extra="ignore")

    employees: int = Field(default=0, ge=0)
    users: int = Field(default=0, ge=0)
    thirdparties: int = Field(default=0, ge=0)
    last_employee_compromised: str | None = None
    last_user_compromised: str | None = None


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


class _Vulnerability(BaseModel):
    model_config = ConfigDict(extra="ignore")

    cve: str = Field(default="", validation_alias=AliasChoices("CVE", "cve"))
    vendor: str | None = Field(default=None, validation_alias=AliasChoices("Vendor", "vendor"))
    product: str | None = Field(default=None, validation_alias=AliasChoices("Product", "product"))
    cvss: object = Field(default=None, validation_alias=AliasChoices("CVSS", "cvss"))
    severity: str | None = None


class _GroupRecord(BaseModel):
    # `locations` (the group's .onion leak sites) and `client` (our account) are
    # deliberately not modelled, so they can never reach state, reports or email.
    model_config = ConfigDict(extra="ignore")

    name: str = Field(validation_alias=AliasChoices("group", "name"))
    description: str | None = None
    added_date: str | None = None
    firstseen: str | None = None
    lastseen: str | None = None
    victims: object = None
    altname: str | None = None
    tools: object = None
    ttps: list[_Tactic] | None = None
    vulnerabilities: object = None
    url: str | None = None


class RansomwareLiveCollector:
    name = "ransomware_live"

    def __init__(
        self,
        client: httpx.AsyncClient,
        base_url: str = "https://api-pro.ransomware.live",
        timeout_seconds: float = 15.0,
        max_items: int = 100,
        api_key: str | None = None,
    ) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._max_items = max_items
        self._headers = {"X-API-KEY": api_key} if api_key else None

    async def collect(self) -> CollectResult:
        try:
            payload = await self._get("/victims/recent")
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if status in (401, 403):
                return self._failed(
                    f"API key missing or rejected (HTTP {status}): check the X-API-KEY "
                    "credential (cloud: environment API credentials; local: "
                    "RANSOMWARE_LIVE_API_KEY)"
                )
            return self._failed(f"{type(exc).__name__}: {exc}")
        except Exception as exc:
            return self._failed(f"{type(exc).__name__}: {exc}")

        victims = payload.get("victims") if isinstance(payload, dict) else None
        if not isinstance(victims, list):
            return self._failed("unexpected payload shape: expected an object with a victims list")

        fetched_at = datetime.now(UTC)
        items: list[RawItem] = []
        skipped = 0
        for raw in victims[: self._max_items]:
            try:
                record = _VictimRecord.model_validate(raw)
            except ValidationError:
                skipped += 1
                continue
            items.append(self._to_item(record, fetched_at))

        if not items and skipped:
            return self._failed(f"all {skipped} records failed validation")
        if skipped:
            logger.warning("records_skipped", source=self.name, skipped=skipped)
        return CollectResult(source=self.name, status=CollectionStatus.OK, items=items)

    async def group_profile(self, name: str) -> GroupProfile:
        """Fetch one group's profile. Raises on any failure; callers treat profiles as
        supplementary and must not turn a failed lookup into a collection failure."""
        payload = await self._get(f"/group/{quote(name, safe='')}")
        return _to_profile(_GroupRecord.model_validate(payload))

    async def _get(self, path: str) -> object:
        url = f"{self._base_url}{path}"
        return await fetch_json(self._client, url, self._timeout, headers=self._headers)

    def _failed(self, error: str) -> CollectResult:
        logger.warning("collect_failed", source=self.name, error=error)
        return CollectResult(source=self.name, status=CollectionStatus.FAILED, error=error)

    def _to_item(self, record: _VictimRecord, fetched_at: datetime) -> RawItem:
        group = record.group or "unknown group"
        external_id = _dedup_id(record.permalink) or f"{record.victim}@{group}@{record.attackdate}"
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
            victim_domain=_host_only(_none_if_missing(record.website)),
            reference_url=_clearnet_https(record.permalink),
            press_url=_clearnet_https(record.press if isinstance(record.press, str) else None),
            infostealer=_infostealer(record.infostealer),
        )


def _dedup_id(permalink: str | None) -> str | None:
    """The permalink in its v2 form, so already-reported victims stay seen: restore the
    base64 '=' padding PRO drops. The token may itself contain '/', so it is cut at the
    known prefix, never at the last slash."""
    if not permalink or not permalink.startswith(_PERMALINK_PREFIX):
        return permalink
    token = permalink[len(_PERMALINK_PREFIX) :]
    return _PERMALINK_PREFIX + token + "=" * (-len(token) % 4)


def _infostealer(value: object) -> InfostealerExposure | None:
    """Counts only (never the stolen data); None when there is nothing to report."""
    if not isinstance(value, dict):
        return None
    try:
        raw = _Infostealer.model_validate(value)
    except ValidationError:
        return None
    if not (raw.employees or raw.users or raw.thirdparties):
        return None
    return InfostealerExposure(
        employees=raw.employees,
        users=raw.users,
        third_parties=raw.thirdparties,
        last_employee_compromised=_parse_day(raw.last_employee_compromised),
        last_user_compromised=_parse_day(raw.last_user_compromised),
    )


def _to_profile(record: _GroupRecord) -> GroupProfile:
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
        first_seen=_parse_day(record.firstseen) or _parse_day(record.added_date),
        last_seen=_parse_day(record.lastseen),
        victim_count=_count(record.victims),
        aliases=[scrub(a) for a in aliases],
        tools=_tools(record.tools),
        tactics=tactics,
        exploited_cves=_exploited_cves(record.vulnerabilities),
        reference_url=_clearnet_https(record.url),
    )


def _tools(value: object) -> dict[str, list[str]]:
    """{category: [tool, …]}; PRO sends one mapping, v2 sent a list of them."""
    blocks = [value] if isinstance(value, dict) else value if isinstance(value, list) else []
    tools: dict[str, list[str]] = {}
    for block in blocks:
        if not isinstance(block, dict):
            continue
        for category, names in block.items():
            if not isinstance(category, str) or not isinstance(names, list):
                continue
            cleaned = [
                clip(scrub(n.strip()), _TOOL_NAME_LIMIT)
                for n in names
                if isinstance(n, str) and n.strip()
            ]
            if cleaned:
                tools.setdefault(scrub(category), []).extend(cleaned)
    return tools


def _exploited_cves(value: object) -> list[ExploitedCve]:
    """Well-formed, de-duplicated CVE entries, highest CVSS first; junk entries are
    dropped one by one rather than failing the whole profile."""
    cves: dict[str, ExploitedCve] = {}
    for entry in value if isinstance(value, list) else []:
        try:
            vuln = _Vulnerability.model_validate(entry)
        except ValidationError:
            continue
        cve_id = vuln.cve.strip().upper()
        if not _CVE_ID.match(cve_id) or cve_id in cves:
            continue
        severity = (vuln.severity or "").strip().lower()
        cves[cve_id] = ExploitedCve(
            cve_id=cve_id,
            vendor=clip(scrub((vuln.vendor or "").strip()), _TOOL_NAME_LIMIT),
            product=clip(scrub((vuln.product or "").strip()), _TOOL_NAME_LIMIT),
            cvss=_cvss(vuln.cvss),
            severity=severity if severity in _SEVERITIES else None,
        )
    return sorted(cves.values(), key=lambda c: (-(c.cvss or 0.0), c.cve_id))


def _cvss(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        return None
    try:
        score = float(value)
    except ValueError:
        return None
    return score if 0.0 <= score <= 10.0 else None


def _count(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _clearnet_https(url: str | None) -> str | None:
    """Only structured https links to clearnet pages are ever shown as references."""
    if not url:
        return None
    url = url.strip()
    if not url.lower().startswith("https://") or ".onion" in url.lower():
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
