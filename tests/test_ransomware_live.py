from __future__ import annotations

import base64
from collections.abc import AsyncIterator

import httpx
import pytest
import respx

from daily_darkweb.collectors.ransomware_live import RansomwareLiveCollector
from daily_darkweb.core.models import CollectionStatus

BASE = "https://api.test.invalid"
URL = f"{BASE}/victims/recent"
PERMALINK = "https://www.ransomware.live/id/"
ONION = "b" * 56 + ".onion"
ACCOUNT = "subscriber@example.com"  # the API echoes the key owner's address as `client`


def token(text: str) -> str:
    """base64 as PRO prints it in permalinks: without '=' padding."""
    return base64.b64encode(text.encode()).decode().rstrip("=")


VICTIM = {
    "victim": "Acme Hospital",
    "group": "qilin",
    "activity": "Healthcare",
    "country": "TH",
    "website": "acme-hospital.example.com",
    "description": "Status: published",
    "attackdate": "2026-07-19T22:20:39+00:00",
    "discovered": "2026-07-19T22:20:57+00:00",
    "permalink": PERMALINK + token("Acme Hospital@qilin"),
    "id": token("Acme Hospital@qilin"),
    "post_url": f"http://{ONION}/acme",
    "screenshot": "https://images.ransomware.live/victims/acme.png",
    "press": None,
    "infostealer": "",
    "ransom": None,
    "data_size": None,
}


def page(*victims: dict[str, object]) -> dict[str, object]:
    return {"client": ACCOUNT, "count": len(victims), "order": "discovered", "victims": victims}


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as c:
        yield c


def make_collector(
    client: httpx.AsyncClient, api_key: str | None = None
) -> RansomwareLiveCollector:
    return RansomwareLiveCollector(
        client, base_url=BASE, timeout_seconds=1.0, max_items=50, api_key=api_key
    )


@respx.mock
async def test_ok_maps_records(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json=page(VICTIM))
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.OK
    item = result.items[0]
    assert item.title == "Acme Hospital claimed by qilin"
    assert item.actor == "qilin"
    assert item.sector == "Healthcare"
    assert item.country == "TH"
    assert item.victim_domain == "acme-hospital.example.com"
    assert item.reference_url == VICTIM["permalink"]
    assert item.press_url is None
    assert item.infostealer is None


@pytest.mark.parametrize(
    "victim_token",
    [
        token("Acme Hospital@qilin"),  # two '=' dropped
        token("AcmeX@qilin"),  # one '=' dropped
        token("Big Retail Co@safepay"),  # no padding at all
        token("Acme Lab??@akira"),  # 'QWNtZSBMYWI/P0Bha2lyYQ': a '/' inside, as seen live
    ],
)
@respx.mock
async def test_dedup_id_is_the_v2_permalink_so_seen_state_carries_over(
    client: httpx.AsyncClient, victim_token: str
) -> None:
    respx.get(URL).respond(json=page(dict(VICTIM, permalink=PERMALINK + victim_token)))
    item = (await make_collector(client).collect()).items[0]
    padded = victim_token + "=" * (-len(victim_token) % 4)
    assert item.external_id == PERMALINK + padded  # the key v2 runs stored in seen-state
    base64.b64decode(padded, validate=True)  # restored padding makes it valid base64 again


@respx.mock
async def test_dedup_id_without_a_permalink_falls_back_to_victim_group_date(
    client: httpx.AsyncClient,
) -> None:
    respx.get(URL).respond(
        json=page(dict(VICTIM, permalink=None), dict(VICTIM, permalink="https://other.example/x"))
    )
    first, second = (await make_collector(client).collect()).items
    assert first.external_id == "Acme Hospital@qilin@2026-07-19 22:20:39+00:00"
    assert second.external_id == "https://other.example/x"  # unknown shapes are kept as-is


@respx.mock
async def test_api_key_header_is_sent_only_when_configured(client: httpx.AsyncClient) -> None:
    route = respx.get(URL).respond(json=page(VICTIM))
    await make_collector(client, api_key="local-key").collect()
    await make_collector(client).collect()  # cloud: the network proxy adds the key
    with_key, without_key = route.calls
    assert with_key.request.headers["X-API-KEY"] == "local-key"
    assert "X-API-KEY" not in without_key.request.headers


@pytest.mark.parametrize("status", [401, 403])
@respx.mock
async def test_rejected_key_fails_closed_with_a_hint_and_no_retry(
    client: httpx.AsyncClient, status: int
) -> None:
    route = respx.get(URL).respond(status_code=status)
    result = await make_collector(client, api_key="wrong").collect()
    assert result.status is CollectionStatus.FAILED
    assert result.error is not None
    assert f"API key missing or rejected (HTTP {status})" in result.error
    assert "wrong" not in result.error
    assert route.call_count == 1


@respx.mock
async def test_leak_site_and_account_fields_never_reach_the_result(
    client: httpx.AsyncClient,
) -> None:
    respx.get(URL).respond(json=page(VICTIM))
    dumped = (await make_collector(client).collect()).model_dump_json()
    assert ".onion" not in dumped  # post_url
    assert "images.ransomware.live" not in dumped  # screenshot
    assert ACCOUNT not in dumped  # client


@respx.mock
async def test_infostealer_exposure_keeps_counts_only(client: httpx.AsyncClient) -> None:
    exposure = {
        "update": "2026-10-06T20:55:38",
        "employees": 3,
        "users": 120,
        "thirdparties": 0,
        "employees_url": 1,
        "users_url": 9,
        "last_employee_compromised": "2026-08-01T10:00:00.000Z",
        "last_user_compromised": None,
        "infostealer_stats": {"lumma": 2},
    }
    respx.get(URL).respond(
        json=page(
            dict(VICTIM, infostealer=exposure),
            dict(VICTIM, infostealer=dict(exposure, employees=0, users=0)),  # nothing to report
            dict(VICTIM, infostealer=dict(exposure, employees="many")),  # malformed
            dict(VICTIM, infostealer=""),
        )
    )
    result = await make_collector(client).collect()
    assert len(result.items) == 4  # a bad enrichment never drops the victim
    found = result.items[0].infostealer
    assert found is not None
    assert (found.employees, found.users, found.third_parties) == (3, 120, 0)
    assert str(found.last_employee_compromised) == "2026-08-01"
    assert found.last_user_compromised is None
    assert [i.infostealer for i in result.items[1:]] == [None, None, None]


@respx.mock
async def test_press_link_is_kept_only_for_clearnet_https(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(
        json=page(
            dict(VICTIM, press="https://news.example/acme-hospital-attack"),
            dict(VICTIM, press=f"https://{ONION}/press"),
            dict(VICTIM, press="http://news.example/plain"),
            dict(VICTIM, press={"url": "https://news.example/x"}),
        )
    )
    items = (await make_collector(client).collect()).items
    assert [i.press_url for i in items] == ["https://news.example/acme-hospital-attack"] + [
        None
    ] * 3


@respx.mock
async def test_placeholder_values_normalized(client: httpx.AsyncClient) -> None:
    record = dict(VICTIM, activity="Not Found", website="", country="  ")
    respx.get(URL).respond(json=page(record))
    item = (await make_collector(client).collect()).items[0]
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


@pytest.mark.parametrize("payload", [[VICTIM], {"error": "nope"}, {"victims": "none"}])
@respx.mock
async def test_unexpected_payload_shape_fails_closed(
    client: httpx.AsyncClient, payload: object
) -> None:
    respx.get(URL).respond(json=payload)
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.FAILED
    assert result.error is not None and "unexpected payload shape" in result.error


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
    route.side_effect = [httpx.Response(500), httpx.Response(200, json=page(VICTIM))]
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.OK
    assert route.call_count == 2


@respx.mock
async def test_all_invalid_records_fails_closed(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json=page({"group": "no-victim-field"}))
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.FAILED


GROUP = {
    "group": "qilin",
    "client": ACCOUNT,
    "added_date": "2022-10-08",
    "firstseen": "2022-10-08T05:43:10.034028+00:00",
    "lastseen": "2026-10-07T00:10:39.005522+00:00",
    "victims": 2342,
    "victims_hidden": False,
    "description": (
        f"Double extortion group. Leak site http://{ONION}/blog, contact ops@onionmail.org"
    ),
    "locations": [{"fqdn": ONION, "slug": f"http://{ONION}/"}],
    "tools": {"CredentialTheft": ["Mimikatz"], "DefenseEvasion": ["EDRSandBlast", " ", None]},
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
    "vulnerabilities": [
        {
            "Vendor": "Fortinet",
            "Product": "FortiOS",
            "CVE": "CVE-2024-21762",
            "CVSS": 9.8,
            "severity": "CRITICAL",
        },
        {
            "Vendor": "SAP",
            "Product": "NetWeaver",
            "CVE": "cve-2025-31324",
            "CVSS": "10",
            "severity": "critical",
        },
        {
            "Vendor": "Veeam",
            "Product": "Backup",
            "CVE": "CVE-2023-27532",
            "CVSS": "n/a",
            "severity": "bogus",
        },
        {"Vendor": "SAP", "Product": "NetWeaver", "CVE": "CVE-2025-31324", "CVSS": 10.0},
        {"Vendor": "x", "Product": "y", "CVE": "not-a-cve"},
        "junk",
    ],
    "has_negotiations": True,
    "negotiation_count": 2,
    "url": "https://www.ransomware.live/group/qilin",
}


@respx.mock
async def test_group_profile_keeps_intel_and_never_leak_sites(client: httpx.AsyncClient) -> None:
    route = respx.get(f"{BASE}/group/qilin").respond(json=GROUP)
    profile = await make_collector(client, api_key="local-key").group_profile("qilin")

    assert route.calls.last.request.headers["X-API-KEY"] == "local-key"
    assert profile.name == "qilin"
    assert str(profile.first_seen) == "2022-10-08"
    assert str(profile.last_seen) == "2026-10-07"
    assert profile.victim_count == 2342
    assert profile.tools == {"CredentialTheft": ["Mimikatz"], "DefenseEvasion": ["EDRSandBlast"]}
    [tactic] = profile.tactics  # nameless tactic and technique are dropped
    assert (tactic.tactic_id, tactic.name) == ("TA0001", "Initial Access")
    assert [t.technique_id for t in tactic.techniques] == ["T1078"]
    assert tactic.techniques[0].details == "Stolen VPN credentials; see [link removed]"
    # Highest CVSS first, de-duplicated, malformed entries dropped one by one.
    assert [(c.cve_id, c.cvss, c.severity) for c in profile.exploited_cves] == [
        ("CVE-2025-31324", 10.0, "critical"),
        ("CVE-2024-21762", 9.8, "critical"),
        ("CVE-2023-27532", None, None),
    ]
    assert (profile.exploited_cves[1].vendor, profile.exploited_cves[1].product) == (
        "Fortinet",
        "FortiOS",
    )
    assert profile.reference_url == "https://www.ransomware.live/group/qilin"
    dumped = profile.model_dump_json()
    assert ".onion" not in dumped
    assert "onionmail" not in dumped
    assert ACCOUNT not in dumped


@respx.mock
async def test_v2_shaped_group_still_parses(client: httpx.AsyncClient) -> None:
    v2 = {
        "name": "qilin",
        "altname": "Agenda, Water Galura",
        "added_date": "2022-10-08",
        "tools": [{"CredentialTheft": ["Mimikatz"]}],
        "ttps": [],
    }
    respx.get(f"{BASE}/group/qilin").respond(json=v2)
    profile = await make_collector(client).group_profile("qilin")
    assert profile.aliases == ["Agenda", "Water Galura"]
    assert profile.tools == {"CredentialTheft": ["Mimikatz"]}
    assert str(profile.first_seen) == "2022-10-08"
    assert profile.victim_count is None
    assert profile.exploited_cves == []


@respx.mock
async def test_group_names_are_url_encoded(client: httpx.AsyncClient) -> None:
    route = respx.get(f"{BASE}/group/Booba%20Project").respond(
        json=dict(GROUP, group="Booba Project", ttps=[], tools={}, vulnerabilities=[])
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
async def test_victim_text_is_scrubbed(client: httpx.AsyncClient) -> None:
    record = dict(VICTIM, description=f"Data at http://{ONION}/x or mail a@b.example")
    respx.get(URL).respond(json=page(record))
    item = (await make_collector(client).collect()).items[0]
    assert ".onion" not in item.body
    assert "a@b.example" not in item.body
    assert "[onion address removed]" in item.body


@respx.mock
async def test_non_https_or_onion_reference_is_dropped(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(
        json=page(
            dict(VICTIM, permalink=f"http://{ONION}/post"),
            dict(VICTIM, permalink="http://x.example/p"),
        )
    )
    items = (await make_collector(client).collect()).items
    assert [i.reference_url for i in items] == [None, None]


@respx.mock
async def test_victim_website_is_reduced_to_its_host(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(
        json=page(
            dict(VICTIM, website="https://www.acme.example/about"),
            dict(VICTIM, website="https:renaldocs.example"),  # malformed, seen in live data
        )
    )
    items = (await make_collector(client).collect()).items
    assert [i.victim_domain for i in items] == ["www.acme.example", "renaldocs.example"]


@respx.mock
async def test_source_markup_and_placeholders_become_plain_text(
    client: httpx.AsyncClient,
) -> None:
    respx.get(URL).respond(
        json=page(
            dict(VICTIM, description="Blocked.<BR> > <BR> > Operating since 2023.<b>x</b>"),
            dict(VICTIM, description="N/A"),
            dict(VICTIM, description="[AI generated] N/A\n\nA regional chain."),
        )
    )
    items = (await make_collector(client).collect()).items
    assert items[0].body == "Blocked. Operating since 2023. x"
    assert items[1].body == ""  # a bare placeholder is no description at all
    assert items[2].body == "[AI generated] N/A A regional chain."  # marker kept for the badge
