"""Dedup keys and filters. Pure; persistence of seen-keys lives in the interface layer."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

from daily_darkweb.core.models import RawItem


def dedup_key(item: RawItem) -> str:
    raw = f"{item.source}|{item.external_id}".lower()
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def dedupe(items: Iterable[RawItem]) -> list[RawItem]:
    seen: set[str] = set()
    unique: list[RawItem] = []
    for item in items:
        key = dedup_key(item)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def filter_new(items: Iterable[RawItem], seen_keys: frozenset[str]) -> list[RawItem]:
    return [item for item in items if dedup_key(item) not in seen_keys]
