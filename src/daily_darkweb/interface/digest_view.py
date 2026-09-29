"""Format-agnostic digest view model, shared by the markdown and HTML renderers.

Splits observations by source so a handful of new CVEs never get crowded out of a
shared top-N slot by ransomware volume (both are useful, but very different in scale).
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from daily_darkweb.core.models import (
    Alert,
    AttackTactic,
    CountDelta,
    GroupProfile,
    RawItem,
    Report,
    Trends,
)
from daily_darkweb.core.sanitize import clip

_VULN_SOURCE = "cisa_kev"
TOP_OBSERVATIONS = 10
TOP_STATS = 5
AI_NOTES_TITLE = "AI analyst notes"
AI_NOTES_DISCLAIMER = (
    "AI generated from this digest by a language model — may be wrong; "
    "verify against the sourced items below before acting."
)
PROFILES_TITLE = "Threat actor profiles"
PROFILES_NOTE = (
    "Who the groups behind today's signals are and how they operate, so no one needs to "
    "visit their sites. Source: ransomware.live (MITRE ATT&CK mapping)."
)
DESCRIPTION_LIMIT = 500
SNIPPET_LIMIT = 140
# Tactics a defence plan acts on, in reading order. Initial Access is shown with the
# group-specific details (prevention); the rest as technique names (detection/response).
DEFENSE_TACTICS = (
    "Initial Access",
    "Defense Evasion",
    "Credential Access",
    "Lateral Movement",
    "Exfiltration",
    "Impact",
)
TECHNIQUES_PER_TACTIC = 4
TOOLS_PER_CATEGORY = 5
_TOOL_CATEGORIES = {
    "CredentialTheft": "Credential theft",
    "DefenseEvasion": "Defense evasion",
    "DiscoveryEnum": "Discovery",
    "LOLBAS": "Living-off-the-land binaries",
    "Offsec": "Offensive security tools",
    "RMM-Tools": "Remote management (RMM) tools",
}

# ransomware.live prefixes descriptions its own AI wrote with this marker.
_SOURCE_AI_MARKER = re.compile(r"^\s*\[\s*ai[\s-]*generated\s*\]\s*", re.IGNORECASE)


def split_ai_generated(text: str) -> tuple[bool, str]:
    """(True, text-without-marker) when a source flags its text as AI-written."""
    stripped, count = _SOURCE_AI_MARKER.subn("", text, count=1)
    return count == 1, stripped


def format_delta(delta: CountDelta) -> str:
    """'42 (prev 30, +40%)' once a previous window exists, else just '42'."""
    if delta.previous is None:
        return str(delta.current)
    if delta.previous == 0:
        change = "new" if delta.current else "±0%"
    else:
        change = f"{(delta.current - delta.previous) / delta.previous:+.0%}"
    return f"{delta.current} (prev {delta.previous}, {change})"


def profiles_by_group(report: Report) -> dict[str, GroupProfile]:
    return {p.name.lower(): p for p in report.group_profiles}


def item_description(item: RawItem, limit: int = DESCRIPTION_LIMIT) -> tuple[bool, str]:
    """A ransomware item's description as one readable paragraph: (source-AI?, text)."""
    source_ai, text = split_ai_generated(item.body)
    return source_ai, clip(" ".join(text.split()), limit)


def detail_lines(item: RawItem) -> list[str]:
    """A KEV item's structured body (vendor/product, summary, required action, …)."""
    return [line.strip() for line in item.body.splitlines() if line.strip()]


def victim_context(item: RawItem) -> str:
    """'Healthcare · US · website example.com' — whichever parts the source provided."""
    parts = [p for p in (item.sector, item.country) if p]
    if item.victim_domain:
        parts.append(f"website {item.victim_domain}")
    return " · ".join(parts)


def tactic_line(tactic: AttackTactic) -> str:
    """'Credential Access: OS Credential Dumping (T1003), … (+2 more)'."""
    shown = tactic.techniques[:TECHNIQUES_PER_TACTIC]
    names = ", ".join(f"{t.name} ({t.technique_id})" for t in shown)
    more = len(tactic.techniques) - len(shown)
    return f"{tactic.name}: {names}" + (f" (+{more} more)" if more > 0 else "")


def defense_tactics(profile: GroupProfile) -> list[AttackTactic]:
    by_name = {t.name.lower(): t for t in profile.tactics if t.techniques}
    return [by_name[name.lower()] for name in DEFENSE_TACTICS if name.lower() in by_name]


def tool_lines(profile: GroupProfile) -> list[str]:
    """'Credential theft: Mimikatz' per category, capped so emails stay readable."""
    lines = []
    for category, tools in profile.tools.items():
        label = _TOOL_CATEGORIES.get(category, category)
        shown = tools[:TOOLS_PER_CATEGORY]
        more = len(tools) - len(shown)
        lines.append(f"{label}: {', '.join(shown)}" + (f" (+{more} more)" if more > 0 else ""))
    return lines


def history_note(trends: Trends) -> str:
    """How much history backs the trends, so readers can judge how much to trust them."""
    note = f"History: {trends.history_days} day(s)"
    if not trends.has_previous:
        note += f"; week-over-week comparison starts at {2 * trends.window_days} days"
    if trends.incomplete_days:
        note += f"; {trends.incomplete_days} day(s) in this window had a collector failure"
    return note


@dataclass(frozen=True)
class DigestView:
    alerts: list[Alert]
    vulnerability_watch: list[Alert]
    landscape_observations: list[Alert]
    landscape_total: int
    top_actors: list[tuple[str, int]]
    top_sectors: list[tuple[str, int]]
    top_countries: list[tuple[str, int]]


def build_view(report: Report) -> DigestView:
    vuln_watch = [a for a in report.observations if a.item.source == _VULN_SOURCE]
    landscape = [a for a in report.observations if a.item.source != _VULN_SOURCE]
    actors = Counter(a.item.actor for a in landscape if a.item.actor)
    sectors = Counter(a.item.sector for a in landscape if a.item.sector)
    countries = Counter(a.item.country for a in landscape if a.item.country)
    return DigestView(
        alerts=report.alerts,
        vulnerability_watch=sorted(vuln_watch, key=lambda a: a.score, reverse=True),
        landscape_observations=landscape,
        landscape_total=len(landscape),
        top_actors=actors.most_common(TOP_STATS),
        top_sectors=sectors.most_common(TOP_STATS),
        top_countries=countries.most_common(TOP_STATS),
    )
