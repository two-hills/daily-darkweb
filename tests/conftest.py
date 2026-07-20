from __future__ import annotations

from datetime import UTC, datetime

import pytest

from daily_darkweb.core.models import RawItem

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)


@pytest.fixture
def now() -> datetime:
    return NOW


def make_item(**overrides: object) -> RawItem:
    defaults: dict[str, object] = {
        "source": "ransomware_live",
        "external_id": "https://www.ransomware.live/id/abc",
        "title": "Acme Hospital claimed by qilin",
        "body": "Status: published",
        "fetched_at": NOW,
        "published_at": NOW,
        "actor": "qilin",
        "sector": "Healthcare Services",
        "country": "TH",
        "victim_domain": "acme-hospital.example.com",
    }
    defaults.update(overrides)
    return RawItem.model_validate(defaults)
