from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import date

import httpx
import pytest
import respx

from daily_darkweb.collectors.hibp import HibpCollector
from daily_darkweb.core.matching import match_item
from daily_darkweb.core.models import CollectionStatus, Watchlist

BASE = "https://hibp.test.invalid/api/v3"
URL = f"{BASE}/breaches"
SINCE = date(2026, 9, 1)

BREACH = {
    "Name": "AngelOne",
    "Title": "Angel One",
    "Domain": "angelone.in",
    "BreachDate": "2023-04-01",
    "AddedDate": "2026-10-07T04:10:00Z",
    "ModifiedDate": "2026-10-07T04:10:00Z",
    "PwnCount": 6765054,
    "Description": (
        'In July 2024, the Indian stock brokerage <a href="https://news.example/angel" '
        'target="_blank">Angel One confirmed a data breach</a>. Contact '
        "dpo@angelone.example &amp; see https://leak.example/dump for &quot;details&quot;."
    ),
    "LogoPath": "https://logos.haveibeenpwned.com/AngelOne.png",
    "DataClasses": ["Email addresses", "Names", "Phone numbers"],
    "IsVerified": True,
    "IsFabricated": False,
    "IsSensitive": False,
    "IsRetired": False,
    "IsSpamList": False,
    "IsMalware": False,
    "IsSubscriptionFree": False,
    "IsStealerLog": False,
}


def breach(**overrides: object) -> dict[str, object]:
    return {**BREACH, **overrides}


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as c:
        yield c


def make_collector(client: httpx.AsyncClient, max_items: int = 50) -> HibpCollector:
    return HibpCollector(
        client, since=SINCE, base_url=BASE, timeout_seconds=1.0, max_items=max_items
    )


@respx.mock
async def test_ok_maps_breach_metadata(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json=[BREACH])
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.OK
    [item] = result.items
    assert item.source == "hibp"
    assert item.external_id == "AngelOne"
    assert item.title == "Angel One: 6,765,054 accounts exposed"
    assert item.body.splitlines() == [
        "Exposed data: Email addresses, Names, Phone numbers",
        "Incident date: 2023-04-01 · added to Have I Been Pwned: 2026-10-07",
        "Country (inferred from the website's .in domain): IN",
    ]
    assert item.victim_domain == "angelone.in"
    assert item.country == "IN"
    assert item.published_at is not None and item.published_at.isoformat().startswith(
        "2026-10-07T04:10"
    )
    assert item.reference_url == "https://haveibeenpwned.com/Breach/AngelOne"


@respx.mock
async def test_summary_is_plain_scrubbed_text(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json=[BREACH])
    [item] = (await make_collector(client).collect()).items
    assert item.summary == (
        "In July 2024, the Indian stock brokerage Angel One confirmed a data breach. "
        'Contact [email removed] & see [link removed] for "details".'
    )
    assert "news.example" not in item.model_dump_json()  # the <a href> goes with the tag
    assert "logos.haveibeenpwned.com" not in item.model_dump_json()


@respx.mock
async def test_breach_keywords_never_fire_on_every_entry(client: httpx.AsyncClient) -> None:
    """Every HIBP description says "breach"; the summary is shown but never matched, and
    generated text avoids the word, so only real interests (here: country) alert."""
    respx.get(URL).respond(json=[BREACH, breach(Name="Shop", Title="Shop", Domain="shop.io")])
    angel, shop = (await make_collector(client).collect()).items
    watchlist = Watchlist(keywords=["breach", "breached", "breaches"], countries=["IN"])
    assert [m.watch_value for m in match_item(angel, watchlist)] == ["IN"]
    assert match_item(shop, watchlist) == []  # .io is a generic ccTLD: no country inferred


@pytest.mark.parametrize(
    ("domain", "country"),
    [
        ("angelone.in", "IN"),
        ("shop.co.jp", "JP"),
        ("bank.com.au", "AU"),
        ("example.co.uk", "GB"),
        ("doublecounter.gg", None),  # generic-use ccTLD
        ("app.io", None),
        ("example.com", None),
        ("", None),
    ],
)
@respx.mock
async def test_country_is_inferred_only_from_real_country_domains(
    client: httpx.AsyncClient, domain: str, country: str | None
) -> None:
    respx.get(URL).respond(json=[breach(Domain=domain)])
    [item] = (await make_collector(client).collect()).items
    assert item.country == country
    assert ("Country (inferred" in item.body) is (country is not None)


@respx.mock
async def test_window_and_non_breach_entries(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(
        json=[
            breach(Name="Old", AddedDate="2026-08-31T23:59:59Z"),  # before `since`
            breach(Name="Spam", IsSpamList=True),
            breach(Name="Fake", IsFabricated=True),
            breach(Name="Gone", IsRetired=True),
            breach(Name="Kept", IsVerified=False, IsStealerLog=True, IsSensitive=True),
            breach(Name="Edge", AddedDate="2026-09-01T00:00:00Z"),  # on `since`: kept
        ]
    )
    items = (await make_collector(client).collect()).items
    assert [i.external_id for i in items] == ["Kept", "Edge"]  # newest first
    assert items[0].body.splitlines()[-1] == (
        "Note: not verified by Have I Been Pwned; collected by infostealer malware; "
        "flagged sensitive by Have I Been Pwned"
    )


@respx.mock
async def test_max_items_keeps_the_newest(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(
        json=[breach(Name=f"B{d}", AddedDate=f"2026-09-{d:02d}T00:00:00Z") for d in (3, 9, 5)]
    )
    items = (await make_collector(client, max_items=2).collect()).items
    assert [i.external_id for i in items] == ["B9", "B5"]


@respx.mock
async def test_missing_breach_date_and_title_fall_back(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json=[breach(BreachDate=None, Title="  ", DataClasses=[])])
    [item] = (await make_collector(client).collect()).items
    assert item.title == "AngelOne: 6,765,054 accounts exposed"
    assert item.body.splitlines()[0] == "Added to Have I Been Pwned: 2026-10-07"


@respx.mock
async def test_some_invalid_records_are_skipped(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json=[BREACH, {"Name": "NoDate"}, "junk"])
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.OK
    assert [i.external_id for i in result.items] == ["AngelOne"]


@respx.mock
async def test_all_invalid_records_fail_closed(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json=[{"Name": "NoDate"}, {"Title": "no name"}])
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.FAILED
    assert result.error == "all 2 records failed validation"


@respx.mock
async def test_nothing_new_is_ok_not_failed(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json=[breach(AddedDate="2020-01-01T00:00:00Z")])
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.OK
    assert result.items == []


@pytest.mark.parametrize("payload", [{"breaches": []}, "nope", 42])
@respx.mock
async def test_unexpected_payload_shape_fails_closed(
    client: httpx.AsyncClient, payload: object
) -> None:
    respx.get(URL).respond(json=payload)
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.FAILED
    assert result.error is not None and "unexpected payload shape" in result.error


@respx.mock
async def test_timeout_fails_closed(client: httpx.AsyncClient) -> None:
    respx.get(URL).mock(side_effect=httpx.ConnectTimeout("boom"))
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.FAILED
    assert result.items == []


@respx.mock
async def test_invalid_json_fails_closed(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(content=b"<html>Cloudflare challenge</html>")
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.FAILED


@respx.mock
async def test_blocked_request_is_not_retried(client: httpx.AsyncClient) -> None:
    route = respx.get(URL).respond(status_code=403)
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.FAILED
    assert route.call_count == 1


@respx.mock
async def test_transient_error_is_retried(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("daily_darkweb.collectors.base._wait", lambda state: 0.0)
    route = respx.get(URL)
    route.side_effect = [httpx.Response(503), httpx.Response(200, json=[BREACH])]
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.OK
    assert route.call_count == 2
