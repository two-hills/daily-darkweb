"""Watchlist matching. Pure and deterministic; item content is data, never interpreted."""

from __future__ import annotations

import re

from daily_darkweb.core.models import Match, MatchField, RawItem, Watchlist


def _word_hit(needle: str, haystack: str) -> bool:
    # Word-boundary match so "cisco" doesn't fire on "San Francisco".
    return re.search(rf"\b{re.escape(needle.lower())}\b", haystack) is not None


def _norm_domain(value: str) -> str:
    v = value.strip().lower()
    for prefix in ("https://", "http://"):
        v = v.removeprefix(prefix)
    v = v.split("/", 1)[0]
    return v.removeprefix("www.")


def _domain_hits(candidate: str | None, watched: str) -> bool:
    if not candidate:
        return False
    cand, watch = _norm_domain(candidate), _norm_domain(watched)
    if not cand or not watch:
        return False
    return cand == watch or cand.endswith("." + watch)


def match_item(item: RawItem, watchlist: Watchlist) -> list[Match]:
    matches: list[Match] = []
    haystack = f"{item.title}\n{item.body}".lower()

    for domain in watchlist.domains:
        if _domain_hits(item.victim_domain, domain) or _norm_domain(domain) in haystack:
            matched = item.victim_domain or domain
            matches.append(Match(field=MatchField.DOMAIN, watch_value=domain, matched_text=matched))

    for org in watchlist.org_names:
        if _word_hit(org, haystack):
            matches.append(Match(field=MatchField.ORG, watch_value=org, matched_text=org))

    for keyword in watchlist.keywords:
        if _word_hit(keyword, haystack):
            matches.append(
                Match(field=MatchField.KEYWORD, watch_value=keyword, matched_text=keyword)
            )

    if item.sector:
        sector_l = item.sector.lower()
        for sector in watchlist.sectors:
            if sector.lower() in sector_l:
                matches.append(
                    Match(field=MatchField.SECTOR, watch_value=sector, matched_text=item.sector)
                )

    if item.country:
        country_l = item.country.strip().lower()
        for country in watchlist.countries:
            if country.strip().lower() == country_l:
                matches.append(
                    Match(field=MatchField.COUNTRY, watch_value=country, matched_text=item.country)
                )

    return matches
