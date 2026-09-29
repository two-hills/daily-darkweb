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


ONION = "b" * 56 + ".onion"
GROUP = {
    "name": "qilin",
    "altname": "Agenda, Water Galura",
    "added_date": "2022-10-08",
    "description": (
        f"Double extortion group. Leak site http://{ONION}/blog, contact ops@onionmail.org"
    ),
    "locations": [{"fqdn": ONION, "slug": f"http://{ONION}/"}],
    "tools": [{"CredentialTheft": ["Mimikatz"], "DefenseEvasion": ["EDRSandBlast", " "]}],
    "ttps": [
        {
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "techniques": [
                {
                    "technique_id": "T1078",
                    "technique_name": "Valid Accounts",
                    "technique_details": "Stolen VPN credentials; see https://evil.example/x",
                },
                {"technique_id": "T9999", "technique_name": "", "technique_details": "dropped"},
            ],
        },
        {"tactic_id": "", "tactic_name": "", "techniques": []},
    ],
    "url": "https://www.ransomware.live/group/qilin",
}


@respx.mock
async def test_victim_text_is_scrubbed_but_dedup_id_is_kept(client: httpx.AsyncClient) -> None:
    record = dict(VICTIM, description=f"Data at http://{ONION}/x or mail a@b.example")
    respx.get(URL).respond(json=[record])
    item = (await make_collector(client).collect()).items[0]
    assert ".onion" not in item.body
    assert "a@b.example" not in item.body
    assert "[onion address removed]" in item.body
    assert item.external_id == VICTIM["url"]  # seen-state continuity


@respx.mock
async def test_non_https_or_onion_reference_is_dropped(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(
        json=[dict(VICTIM, url=f"http://{ONION}/post"), dict(VICTIM, url="http://x.example/p")]
    )
    items = (await make_collector(client).collect()).items
    assert [i.reference_url for i in items] == [None, None]


@respx.mock
async def test_group_profile_keeps_ttps_and_never_leak_sites(client: httpx.AsyncClient) -> None:
    respx.get(f"{BASE}/group/qilin").respond(json=GROUP)
    profile = await make_collector(client).group_profile("qilin")

    assert profile.name == "qilin"
    assert profile.first_seen is not None and profile.first_seen.isoformat() == "2022-10-08"
    assert profile.aliases == ["Agenda", "Water Galura"]
    assert profile.tools == {"CredentialTheft": ["Mimikatz"], "DefenseEvasion": ["EDRSandBlast"]}
    [tactic] = profile.tactics  # nameless tactic and technique are dropped
    assert (tactic.tactic_id, tactic.name) == ("TA0001", "Initial Access")
    assert [t.technique_id for t in tactic.techniques] == ["T1078"]
    assert tactic.techniques[0].details == "Stolen VPN credentials; see [link removed]"
    assert profile.reference_url == "https://www.ransomware.live/group/qilin"
    dumped = profile.model_dump_json()
    assert ".onion" not in dumped
    assert "onionmail" not in dumped


@respx.mock
async def test_group_names_are_url_encoded(client: httpx.AsyncClient) -> None:
    route = respx.get(f"{BASE}/group/Booba%20Project").respond(
        json=dict(GROUP, name="Booba Project", ttps=[], tools=[])
    )
    profile = await make_collector(client).group_profile("Booba Project")
    assert route.called
    assert profile.tactics == []


@respx.mock
async def test_unknown_group_raises_for_the_caller_to_note(client: httpx.AsyncClient) -> None:
    respx.get(f"{BASE}/group/nobody").respond(status_code=404)
    with pytest.raises(httpx.HTTPStatusError):
        await make_collector(client).group_profile("nobody")


@respx.mock
async def test_victim_website_is_reduced_to_its_host(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(
        json=[
            dict(VICTIM, domain="https://www.acme.example/about"),
            dict(VICTIM, domain="https:renaldocs.example"),  # malformed, seen in live data
        ]
    )
    items = (await make_collector(client).collect()).items
    assert [i.victim_domain for i in items] == ["www.acme.example", "renaldocs.example"]


@respx.mock
async def test_source_markup_and_placeholders_become_plain_text(
    client: httpx.AsyncClient,
) -> None:
    respx.get(URL).respond(
        json=[
            dict(VICTIM, description="Blocked.<BR> > <BR> > Operating since 2023.<b>x</b>"),
            dict(VICTIM, description="N/A"),
            dict(VICTIM, description="[AI generated] N/A\n\nA regional chain."),
        ]
    )
    items = (await make_collector(client).collect()).items
    assert items[0].body == "Blocked. Operating since 2023. x"
    assert items[1].body == ""  # a bare placeholder is no description at all
    assert items[2].body == "[AI generated] N/A A regional chain."  # marker kept for the badge
