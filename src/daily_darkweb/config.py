"""Config loading and validation. All YAML parsed with safe_load only."""

from __future__ import annotations

from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel, model_validator

from daily_darkweb.core.models import Watchlist


class RansomwareLiveConfig(BaseModel):
    enabled: bool = True
    base_url: str = "https://api.ransomware.live/v2"
    timeout_seconds: float = 15.0
    max_items: int = 100


class CisaKevConfig(BaseModel):
    enabled: bool = True
    feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    timeout_seconds: float = 30.0
    recent_days: int = 30
    max_items: int = 200


class TorOnionConfig(BaseModel):
    """Placeholder. Stays disabled until a sanctioned CTI program with legal cover exists."""

    enabled: bool = False

    @model_validator(mode="after")
    def _legal_gate(self) -> Self:
        if self.enabled:
            raise ValueError(
                "Tor collector is gated: not implemented and requires documented "
                "legal approval before it can be enabled (see docs/architecture.md)."
            )
        return self


class SourcesConfig(BaseModel):
    ransomware_live: RansomwareLiveConfig = RansomwareLiveConfig()
    cisa_kev: CisaKevConfig = CisaKevConfig()
    tor_onion: TorOnionConfig = TorOnionConfig()


def _load_yaml(path: Path) -> object:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_watchlist(path: Path) -> Watchlist:
    return Watchlist.model_validate(_load_yaml(path) or {})


def load_sources(path: Path) -> SourcesConfig:
    return SourcesConfig.model_validate(_load_yaml(path) or {})
