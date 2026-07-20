from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import respx

from daily_darkweb.collectors.ransomware_live import RansomwareLiveCollector
from daily_darkweb.core.models import CollectionStatus

BASE = "https://api.test.invalid/v2"
URL = f"{BASE}/recentvictims"

VICTIM = {
    "victim": "Acme Hospital",
    "group": "qilin",
    "activity": "Healthcare",
    "country": "TH",
    "domain": "acme-hospital.example.com",
    "description": "Status: published",
    "attackdate": "2026-07-19T22:20:39+00:00",
    "discovered": "2026-07-19T22:20:57+00:00",
    "url": "https://www.ransomware.live/id/abc",
}


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as c:
        yield c


def make_collector(client: httpx.AsyncClient) -> RansomwareLiveCollector:
    return RansomwareLiveCollector(client, base_url=BASE, timeout_seconds=1.0, max_items=50)


@respx.mock
async def test_ok_maps_records(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json=[VICTIM])
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.OK
    item = result.items[0]
    assert item.title == "Acme Hospital claimed by qilin"
    assert item.actor == "qilin"
    assert item.sector == "Healthcare"
    assert item.victim_domain == "acme-hospital.example.com"
    assert item.external_id == VICTIM["url"]


@respx.mock
async def test_placeholder_values_normalized(client: httpx.AsyncClient) -> None:
    record = dict(VICTIM, activity="Not Found", domain="", country="  ")
    respx.get(URL).respond(json=[record])
    result = await make_collector(client).collect()
    item = result.items[0]
    assert item.sector is None
    assert item.victim_domain is None
    assert item.country is None


@respx.mock
async def test_timeout_fails_closed(client: httpx.AsyncClient) -> None:
    respx.get(URL).mock(side_effect=httpx.ConnectTimeout("boom"))
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.FAILED
    assert result.items == []
    assert result.error is not None


@respx.mock
async def test_non_list_payload_fails_closed(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json={"error": "nope"})
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.FAILED


@respx.mock
async def test_invalid_json_fails_closed(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(content=b"<html>not json</html>")
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.FAILED


@respx.mock
async def test_retries_transient_500_then_succeeds(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("daily_darkweb.collectors.base._wait", lambda state: 0.0)
    route = respx.get(URL)
    route.side_effect = [httpx.Response(500), httpx.Response(200, json=[VICTIM])]
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.OK
    assert route.call_count == 2


@respx.mock
async def test_auth_4xx_not_retried(client: httpx.AsyncClient) -> None:
    route = respx.get(URL)
    route.respond(status_code=403)
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.FAILED
    assert route.call_count == 1


@respx.mock
async def test_all_invalid_records_fails_closed(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json=[{"group": "no-victim-field"}])
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.FAILED
