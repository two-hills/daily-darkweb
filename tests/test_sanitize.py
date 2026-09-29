from __future__ import annotations

import pytest

from daily_darkweb.core.sanitize import (
    EMAIL_MARKER,
    LINK_MARKER,
    ONION_MARKER,
    clip,
    scrub,
)

ONION_V3 = "a" * 56 + ".onion"
ONION_V2 = "abcdefghijklmnop.onion"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"visit http://{ONION_V3}/leak/123 now", f"visit {ONION_MARKER} now"),
        (f"mirror {ONION_V2}", f"mirror {ONION_MARKER}"),
        (f"HTTPS://{ONION_V2.upper()}", ONION_MARKER),
        ("files at https://mega.nz/file/abc#key today", f"files at {LINK_MARKER} today"),
        ("dump: ftp://files.example/dump.7z", f"dump: {LINK_MARKER}"),
        ("contact recovery@onionmail.org for terms", f"contact {EMAIL_MARKER} for terms"),
    ],
)
def test_links_emails_and_onions_are_removed(text: str, expected: str) -> None:
    assert scrub(text) == expected


def test_bare_domains_identify_the_victim_and_are_kept() -> None:
    text = "carolinaasthma.com claimed by chaos; see www.example.com"
    assert scrub(text) == text


def test_scrub_is_idempotent() -> None:
    text = f"x http://{ONION_V2}/a y https://e.example/b z a@b.example"
    assert scrub(scrub(text)) == scrub(text)


def test_clip_cuts_on_a_word_boundary_and_marks_it() -> None:
    assert clip("short text", 50) == "short text"
    clipped = clip("one two three four five, six seven", 20)
    assert clipped == "one two three four…"
    assert len(clipped) <= 20
