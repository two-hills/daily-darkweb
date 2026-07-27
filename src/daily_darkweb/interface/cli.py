from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx

from daily_darkweb.collectors.base import Collector
from daily_darkweb.collectors.cisa_kev import CisaKevCollector
from daily_darkweb.collectors.ransomware_live import RansomwareLiveCollector
from daily_darkweb.config import SourcesConfig, load_sources, load_watchlist
from daily_darkweb.core.dedup import dedup_key
from daily_darkweb.core.models import Report
from daily_darkweb.interface.render import render_markdown
from daily_darkweb.interface.render_html import render_html
from daily_darkweb.orchestration.pipeline import run_pipeline

_MAX_SEEN_KEYS = 50_000


def _build_collectors(sources: SourcesConfig, client: httpx.AsyncClient) -> list[Collector]:
    collectors: list[Collector] = []
    if sources.ransomware_live.enabled:
        collectors.append(
            RansomwareLiveCollector(
                client,
                base_url=sources.ransomware_live.base_url,
                timeout_seconds=sources.ransomware_live.timeout_seconds,
                max_items=sources.ransomware_live.max_items,
            )
        )
    if sources.cisa_kev.enabled:
        collectors.append(
            CisaKevCollector(
                client,
                feed_url=sources.cisa_kev.feed_url,
                timeout_seconds=sources.cisa_kev.timeout_seconds,
                recent_days=sources.cisa_kev.recent_days,
                max_items=sources.cisa_kev.max_items,
            )
        )
    return collectors


def _load_seen(path: Path) -> frozenset[str]:
    if not path.exists():
        return frozenset()
    data = json.loads(path.read_text(encoding="utf-8"))
    return frozenset(str(k) for k in data.get("seen", []))


def _save_seen(path: Path, seen: frozenset[str], report: Report) -> None:
    new_keys = [dedup_key(a.item) for a in report.alerts + report.observations]
    merged = (list(seen) + new_keys)[-_MAX_SEEN_KEYS:]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"seen": merged}), encoding="utf-8")


async def _run(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    watchlist = load_watchlist(config_dir / "watchlist.yaml")
    sources = load_sources(config_dir / "sources.yaml")

    state_path = Path(args.state)
    seen = frozenset() if args.no_state else _load_seen(state_path)

    async with httpx.AsyncClient(
        headers={"User-Agent": "daily-darkweb/0.1 (defensive CTI research)"}
    ) as client:
        collectors = _build_collectors(sources, client)
        if not collectors:
            print("No collectors enabled; nothing to do.", file=sys.stderr)
            return 2
        report = await run_pipeline(collectors, watchlist, seen, now=datetime.now(UTC))

    if args.format == "json":
        print(report.model_dump_json(indent=2))
    elif args.format == "html":
        print(render_html(report))
    else:
        print(render_markdown(report))

    if args.html_out:
        html_path = Path(args.html_out)
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(render_html(report), encoding="utf-8")

    if not args.no_state:
        _save_seen(state_path, seen, report)

    # Fail-closed exit codes: alerts and collection failures must be visible to schedulers.
    if report.has_failures:
        return 3
    return 1 if report.alerts else 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="daily-darkweb", description="CTI collection digest")
    parser.add_argument(
        "--config-dir", default="config", help="dir with watchlist.yaml/sources.yaml"
    )
    parser.add_argument("--state", default=".state/seen.json", help="seen-items state file")
    parser.add_argument("--no-state", action="store_true", help="ignore and don't update state")
    parser.add_argument("--format", choices=["md", "json", "html"], default="md")
    parser.add_argument(
        "--html-out", default=None, help="also write a browsable HTML digest to this path"
    )
    args = parser.parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
