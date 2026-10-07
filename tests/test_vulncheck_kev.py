from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import date
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from daily_darkweb.collectors.vulncheck_kev import VulnCheckKevCollector
from daily_darkweb.core.models import CollectionStatus

BASE = "https://vulncheck.test.invalid/v3"
URL = f"{BASE}/index/vulncheck-kev"
SINCE = date(2026, 10, 1)

ONLY_VULNCHECK = {
    "cve": ["CVE-2026-51886"],
    "vendorProject": "Langflow",
    "product": "Langflow",
    "vulnerabilityName": "Langflow Code Injection",
    "shortDescription": "Remote code execution; details at https://exploit.example/x",
    "required_action": "Apply remediations or mitigations per vendor instructions.",
    "knownRansomwareCampaignUse": "Known",
    "cwes": ["CWE-94"],
    "date_added": "2026-10-06T00:00:00Z",
    "updated_at": "2026-10-06T00:00:00Z",
    "vulncheck_reported_exploitation": [
        {"url": "https://report.example/1", "date_added": "2026-10-06T00:00:00Z"},
        {"url": "https://report.example/2", "date_added": "2026-10-06T00:00:00Z"},
    ],
    "vulncheck_xdb": [{"xdb_id": "abc"}],
    "reported_exploited_by_vulncheck_canaries": True,
}
IN_CISA = {
    **ONLY_VULNCHECK,
    "cve": ["CVE-2026-88779"],
    "cisa_date_added": "2026-10-04T00:00:00Z",
    "dueDate": "2026-10-25T00:00:00Z",
}


def record(**overrides: object) -> dict[str, object]:
    return {**ONLY_VULNCHECK, **overrides}


def page(*rows: dict[str, object], total_pages: int = 1) -> dict[str, object]:
    return {"_meta": {"total_pages": total_pages, "max_pages": 6}, "data": list(rows)}


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as c:
        yield c


def make_collector(
    client: httpx.AsyncClient, max_items: int = 50, api_token: str | None = None
) -> VulnCheckKevCollector:
    return VulnCheckKevCollector(
        client,
        since=SINCE,
        base_url=BASE,
        timeout_seconds=1.0,
        max_items=max_items,
        api_token=api_token,
    )


@respx.mock
async def test_maps_an_exploited_cve_cisa_has_not_listed(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json=page(ONLY_VULNCHECK, IN_CISA))
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.OK
    [item] = result.items  # the CISA-listed one is left to the CISA KEV collector
    assert item.source == "vulncheck_kev"
    assert item.external_id == "CVE-2026-51886"
    assert item.title == "CVE-2026-51886: Langflow Code Injection"
    assert item.body.splitlines() == [
        "Vendor: Langflow | Product: Langflow",
        "Remote code execution; details at [link removed]",
        "Required action: Apply remediations or mitigations per vendor instructions.",
        "Known use in ransomware campaigns.",
        "Exploitation evidence: 2 public reports, VulnCheck's own sensors (canaries)",
        "Public exploit code: 1 known",
        "CWE: CWE-94",
        "Not yet in CISA KEV.",
    ]
    assert item.published_at is not None and item.published_at.date() == date(2026, 10, 6)
    assert item.due_date is None
    assert item.reference_url == "https://nvd.nist.gov/vuln/detail/CVE-2026-51886"
    assert "report.example" not in item.model_dump_json()  # evidence is counted, not linked


@respx.mock
async def test_queries_newest_first_from_the_window_start(client: httpx.AsyncClient) -> None:
    route = respx.get(URL).respond(json=page(ONLY_VULNCHECK))
    await make_collector(client).collect()
    query = parse_qs(urlparse(str(route.calls.last.request.url)).query)
    assert query["pubStartDate"] == ["2026-10-01"]
    assert (query["sort"], query["order"], query["page"]) == (["date_added"], ["desc"], ["1"])


@respx.mock
async def test_bearer_token_is_sent_only_when_configured(client: httpx.AsyncClient) -> None:
    route = respx.get(URL).respond(json=page(ONLY_VULNCHECK))
    await make_collector(client, api_token="local-token").collect()
    await make_collector(client).collect()  # cloud: the network proxy adds the token
    with_token, without_token = route.calls
    assert with_token.request.headers["Authorization"] == "Bearer local-token"
    assert "Authorization" not in without_token.request.headers


@pytest.mark.parametrize("status", [401, 403])
@respx.mock
async def test_rejected_token_fails_closed_with_a_hint_and_no_retry(
    client: httpx.AsyncClient, status: int
) -> None:
    route = respx.get(URL).respond(status_code=status)
    result = await make_collector(client, api_token="wrong").collect()
    assert result.status is CollectionStatus.FAILED
    assert result.error is not None
    assert f"API token missing or rejected (HTTP {status})" in result.error
    assert "unused for 30 days expire" in result.error
    assert "wrong" not in result.error
    assert route.call_count == 1


@respx.mock
async def test_pages_until_enough_items(client: httpx.AsyncClient) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        number = int(parse_qs(urlparse(str(request.url)).query)["page"][0])
        rows = [record(cve=[f"CVE-2026-{number}000{i}"]) for i in range(2)]
        return httpx.Response(200, json=page(*rows, total_pages=10))

    route = respx.get(URL).mock(side_effect=respond)
    items = (await make_collector(client, max_items=5).collect()).items
    assert route.call_count == 3  # 2 + 2 + 2 rows: enough after the third page
    assert len(items) == 5


@respx.mock
async def test_never_reads_past_the_api_page_limit(client: httpx.AsyncClient) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        number = int(parse_qs(urlparse(str(request.url)).query)["page"][0])
        return httpx.Response(
            200, json=page(record(cve=[f"CVE-2026-9{number:04d}"]), total_pages=50)
        )

    route = respx.get(URL).mock(side_effect=respond)
    items = (await make_collector(client, max_items=100).collect()).items
    assert route.call_count == 6
    assert len(items) == 6


@respx.mock
async def test_keeps_the_newest_and_drops_out_of_window_rows(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(
        json=page(
            record(cve=["CVE-2026-1001"], date_added="2026-10-02T00:00:00Z"),
            record(cve=["CVE-2026-1003"], date_added="2026-10-05T00:00:00Z"),
            record(cve=["CVE-2026-1002"], date_added="2026-10-03T00:00:00Z"),
            record(cve=["CVE-2026-1000"], date_added="2026-09-30T23:59:59Z"),  # before since
        )
    )
    items = (await make_collector(client, max_items=2).collect()).items
    assert [i.external_id for i in items] == ["CVE-2026-1003", "CVE-2026-1002"]


@respx.mock
async def test_bad_records_are_skipped_but_all_bad_fails_closed(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json=page(ONLY_VULNCHECK, record(cve=["not-a-cve"]), {"cve": []}))
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.OK
    assert [i.external_id for i in result.items] == ["CVE-2026-51886"]

    respx.get(URL).respond(json=page(record(cve=None), {"date_added": "nope"}))
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.FAILED
    assert result.error == "all 2 records failed validation"


@respx.mock
async def test_quiet_window_is_ok_not_failed(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(json=page())
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.OK
    assert result.items == []


@respx.mock
async def test_sparse_records_still_map(client: httpx.AsyncClient) -> None:
    respx.get(URL).respond(
        json=page(
            {
                "cve": ["CVE-2026-2000"],
                "date_added": "2026-10-06T00:00:00Z",
                "vulnerabilityName": "   Cross-site   Scripting ",
                "vendorProject": None,
                "cwes": None,
                "vulncheck_xdb": None,
            }
        )
    )
    [item] = (await make_collector(client).collect()).items
    assert item.title == "CVE-2026-2000: Cross-site Scripting"
    assert item.body.splitlines() == [
        "Vendor: unknown | Product: unknown",
        "Not yet in CISA KEV.",
    ]


@pytest.mark.parametrize("payload", [[ONLY_VULNCHECK], {"data": "none"}, {"error": "x"}])
@respx.mock
async def test_unexpected_payload_shape_fails_closed(
    client: httpx.AsyncClient, payload: object
) -> None:
    respx.get(URL).respond(json=payload)
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.FAILED
    assert result.error is not None and "unexpected payload shape" in result.error


@respx.mock
async def test_timeout_fails_closed(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("daily_darkweb.collectors.base._wait", lambda state: 0.0)
    respx.get(URL).mock(side_effect=httpx.ConnectTimeout("boom"))
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.FAILED
    assert result.items == []


@respx.mock
async def test_transient_error_is_retried(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("daily_darkweb.collectors.base._wait", lambda state: 0.0)
    route = respx.get(URL)
    route.side_effect = [httpx.Response(429), httpx.Response(200, json=page(ONLY_VULNCHECK))]
    result = await make_collector(client).collect()
    assert result.status is CollectionStatus.OK
    assert route.call_count == 2
