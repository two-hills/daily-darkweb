"""Config loading and validation. All YAML parsed with safe_load only."""

from __future__ import annotations

from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from daily_darkweb.core.models import Watchlist


class ApiKeys(BaseSettings):
    """API keys for local runs, from env/.env — never from the committed config.

    Cloud Routine runs leave these unset: the session's network proxy adds each key to
    requests for its API host, so no key ever enters the session (docs/operations.md).
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    ransomware_live_api_key: SecretStr | None = None


class RansomwareLiveConfig(BaseModel):
    enabled: bool = True
    # API PRO (free key). The keyless v2 API is personal-use only and rate-limited.
    base_url: str = "https://api-pro.ransomware.live"
    timeout_seconds: float = 15.0
    max_items: int = 100
    # Threat-actor profiles fetched per run (alert groups first); 0 disables the lookups.
    group_profiles: int = Field(default=5, ge=0, le=10)


class CisaKevConfig(BaseModel):
    enabled: bool = True
    feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    timeout_seconds: float = 30.0
    recent_days: int = 30
    max_items: int = 200


class HibpConfig(BaseModel):
    """Have I Been Pwned's public breach catalogue (no key; CC BY 4.0, credited)."""

    enabled: bool = True
    base_url: str = "https://haveibeenpwned.com/api/v3"
    timeout_seconds: float = 30.0
    recent_days: int = 30  # minimum lookback on AddedDate; widened to cover run gaps
    max_items: int = 50


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
    hibp: HibpConfig = HibpConfig()
    tor_onion: TorOnionConfig = TorOnionConfig()


def _load_yaml(path: Path) -> object:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_watchlist(path: Path) -> Watchlist:
    return Watchlist.model_validate(_load_yaml(path) or {})


def load_sources(path: Path) -> SourcesConfig:
    return SourcesConfig.model_validate(_load_yaml(path) or {})
