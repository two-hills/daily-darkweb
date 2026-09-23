from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import date

import httpx
import pytest
import respx

from daily_darkweb.collectors.cisa_kev import CisaKevCollector
from daily_darkweb.core.models import CollectionStatus

URL = "https://kev.test.invalid/feed.json"
SINCE = date(2026, 7, 1)

RECENT_VULN = {
    "cveID": "CVE-2026-1234",
    "vendorProject": "Cisco",
    "product": "ASA",
    "vulnerabilityName": "Cisco ASA Remote Code Execution Vulnerability",
    "dateAdded": "2026-07-15",
    "dueDate": "2026-07-29",
    "shortDescription": "Cisco ASA contains an RCE vulnerability.",
    "requiredAction": "Apply updates per vendor instructions.",
    "knownRansomwareCampaignUse": "Known",
    "cwes": ["CWE-78"],
}

OLD_VULN = dict(RECENT_VULN, cveID="CVE-2020-0001", dateAdded="2020-01-01")
UNDATED_VULN = {k: v for k, v in RECENT_VULN.items() if k != "dateAdded"} | {
    "cveID": "CVE-2026-9999"
}


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as c:
        yield c


def make_collector(
    client: httpx.AsyncClient, since: date = SINCE, max_items: int = 200
) -> CisaKevCollector:
    return CisaKevCollector(
        client, since=since, feed_url=URL, timeout_seconds=1.0, max_items=max_items
    )


@respx.mock
async def test_maps_entries_in_window_only(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json={"vulnerabilities": [RECENT_VULN, OLD_VULN, UNDATED_VULN]})
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.OK
    assert len(result.items) == 1
    item = result.items[0]
    assert item.external_id == "CVE-2026-1234"
    assert "Cisco" in item.body
    assert "ransomware campaigns" in item.body
    assert "CWE-78" in item.body
    assert item.reference_url == "https://nvd.nist.gov/vuln/detail/CVE-2026-1234"
    assert item.published_at is not None
    assert item.due_date is not None
    assert item.due_date.date().isoformat() == "2026-07-29"


@respx.mock
async def test_since_is_inclusive(client: httpx.AsyncClient) -> None:
    boundary = dict(RECENT_VULN, cveID="CVE-2026-0700", dateAdded=SINCE.isoformat())
    respx.get(URL).respond(json={"vulnerabilities": [boundary]})
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.OK
    assert [i.external_id for i in result.items] == ["CVE-2026-0700"]


@respx.mock
async def test_wider_window_recovers_older_entries(client: httpx.AsyncClient) -> None:
    """The sparse-run case: entries outside the default window are picked up when the
    caller passes a `since` stretched back to the last successful run."""
    gap_vuln = dict(RECENT_VULN, cveID="CVE-2026-73570", dateAdded="2026-08-19")
    respx.get(URL).respond(json={"vulnerabilities": [gap_vuln]})

    narrow = await make_collector(client, since=date(2026, 8, 24)).collect()
    assert narrow.status is CollectionStatus.OK
    assert narrow.items == []

    wide = await make_collector(client, since=date(2026, 8, 18)).collect()
    assert wide.status is CollectionStatus.OK
    assert [i.external_id for i in wide.items] == ["CVE-2026-73570"]


@respx.mock
async def test_max_items_keeps_newest_entries(client: httpx.AsyncClient) -> None:
    feed = [
        dict(RECENT_VULN, cveID=f"CVE-2026-000{i}", dateAdded=f"2026-07-1{i}") for i in (1, 3, 2)
    ]
    respx.get(URL).respond(json={"vulnerabilities": feed})
    result = await make_collector(client, max_items=2).collect()
    assert result.status is CollectionStatus.OK
    assert [i.external_id for i in result.items] == ["CVE-2026-0003", "CVE-2026-0002"]


@respx.mock
async def test_no_recent_entries_is_ok_not_failed(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json={"vulnerabilities": [OLD_VULN]})
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.OK
    assert result.items == []


@respx.mock
async def test_timeout_fails_closed(client: httpx.AsyncClient) -> None:
    respx.get(URL).mock(side_effect=httpx.ConnectTimeout("boom"))
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.FAILED
    assert result.error is not None


@respx.mock
async def test_wrong_shape_fails_closed(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json=[RECENT_VULN])
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.FAILED


@respx.mock
async def test_all_invalid_records_fails_closed(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json={"vulnerabilities": [{"noCveId": True}]})
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.FAILED
