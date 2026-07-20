from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import respx

from daily_darkweb.collectors.cisa_kev import CisaKevCollector
from daily_darkweb.core.models import CollectionStatus

URL = "https://kev.test.invalid/feed.json"

RECENT_VULN = {
    "cveID": "CVE-2026-1234",
    "vendorProject": "Cisco",
    "product": "ASA",
    "vulnerabilityName": "Cisco ASA Remote Code Execution Vulnerability",
    "dateAdded": "2026-07-15",
    "shortDescription": "Cisco ASA contains an RCE vulnerability.",
    "requiredAction": "Apply updates per vendor instructions.",
    "knownRansomwareCampaignUse": "Known",
}

OLD_VULN = dict(RECENT_VULN, cveID="CVE-2020-0001", dateAdded="2020-01-01")


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as c:
        yield c


def make_collector(client: httpx.AsyncClient, recent_days: int = 30) -> CisaKevCollector:
    return CisaKevCollector(client, feed_url=URL, timeout_seconds=1.0, recent_days=recent_days)


@respx.mock
async def test_maps_recent_entries_only(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json={"vulnerabilities": [RECENT_VULN, OLD_VULN]})
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.OK
    assert len(result.items) == 1
    item = result.items[0]
    assert item.external_id == "CVE-2026-1234"
    assert "Cisco" in item.body
    assert "ransomware campaigns" in item.body
    assert item.reference_url == "https://nvd.nist.gov/vuln/detail/CVE-2026-1234"
    assert item.published_at is not None


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
