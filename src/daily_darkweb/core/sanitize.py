"""Scrubbing of scraped free text. Pure and deterministic: no I/O, no network, no AI.

Readers of the digest must never be one click away from a leak site or a stolen-data
dump, so every scraped text field passes through `scrub` at the collector boundary:
.onion addresses, URLs with a scheme and email addresses are replaced with a marker.
Bare domains are kept on purpose — a victim's own website identifies the victim.
Reference links the digest does show come from structured fields (a clearnet page per
victim, group or CVE), never from scraped prose.
"""

from __future__ import annotations

import re

ONION_MARKER = "[onion address removed]"
LINK_MARKER = "[link removed]"
EMAIL_MARKER = "[email removed]"

# Order matters: onion addresses first (with or without a scheme), then any other
# scheme://… link, then email addresses.
_ONION = re.compile(r"(?i)\b(?:[a-z][a-z0-9+.-]*://)?[a-z2-7]{16,56}\.onion\b\S*")
_URL = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://\S+")
_EMAIL = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b")


def scrub(text: str) -> str:
    text = _ONION.sub(ONION_MARKER, text)
    text = _URL.sub(LINK_MARKER, text)
    return _EMAIL.sub(EMAIL_MARKER, text)


def clip(text: str, limit: int) -> str:
    """Shorten to at most `limit` characters on a word boundary, marking the cut."""
    text = text.strip()
    if len(text) <= limit:
        return text
    cut = text[: limit - 1].rsplit(" ", 1)[0].rstrip(" ,;:")
    return cut + "…"
