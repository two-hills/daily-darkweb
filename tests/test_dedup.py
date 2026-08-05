from __future__ import annotations

from daily_darkweb.core.dedup import dedup_key, dedupe, filter_new
from tests.conftest import make_item


def test_key_stable_and_case_insensitive() -> None:
    a = make_item(external_id="ABC")
    b = make_item(external_id="abc")
    assert dedup_key(a) == dedup_key(b)


def test_key_differs_by_source() -> None:
    a = make_item(source="ransomware_live")
    b = make_item(source="hibp")
    assert dedup_key(a) != dedup_key(b)


def test_dedupe_preserves_first_occurrence() -> None:
    first = make_item(external_id="x", title="first")
    dup = make_item(external_id="x", title="dup")
    other = make_item(external_id="y")
    assert dedupe([first, dup, other]) == [first, other]


def test_filter_new_drops_seen() -> None:
    seen_item = make_item(external_id="seen")
    fresh = make_item(external_id="fresh")
    seen = frozenset({dedup_key(seen_item)})
    assert filter_new([seen_item, fresh], seen) == [fresh]
