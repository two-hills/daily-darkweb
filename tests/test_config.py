from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from daily_darkweb.config import load_sources, load_watchlist


def test_load_watchlist(tmp_path: Path) -> None:
    p = tmp_path / "watchlist.yaml"
    p.write_text("org_names: [Acme]\ndomains: [acme.io]\n", encoding="utf-8")
    wl = load_watchlist(p)
    assert wl.org_names == ["Acme"]
    assert wl.sectors == []


def test_empty_watchlist_ok(tmp_path: Path) -> None:
    p = tmp_path / "watchlist.yaml"
    p.write_text("", encoding="utf-8")
    assert load_watchlist(p).domains == []


def test_tor_collector_is_legally_gated(tmp_path: Path) -> None:
    p = tmp_path / "sources.yaml"
    p.write_text("tor_onion:\n  enabled: true\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="legal approval"):
        load_sources(p)


def test_yaml_payload_is_data_not_code(tmp_path: Path) -> None:
    # safe_load must reject python object construction attempts.
    p = tmp_path / "watchlist.yaml"
    p.write_text("!!python/object/apply:os.system ['echo pwned']", encoding="utf-8")
    with pytest.raises(Exception):  # noqa: B017 - any parse/validation error is fine, code must not run
        load_watchlist(p)
