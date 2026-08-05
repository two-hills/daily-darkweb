from __future__ import annotations

import argparse
import asyncio
import json
import smtplib
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx
from pydantic import ValidationError

from daily_darkweb.collectors.base import Collector
from daily_darkweb.collectors.cisa_kev import CisaKevCollector
from daily_darkweb.collectors.ransomware_live import RansomwareLiveCollector
from daily_darkweb.config import SourcesConfig, load_sources, load_watchlist
from daily_darkweb.core.dedup import dedup_key
from daily_darkweb.core.models import Report
from daily_darkweb.interface.email_send import (
    EmailConfig,
    build_message,
    send_message,
    should_notify,
)
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


def _maybe_send_email(report: Report, html_body: str) -> None:
    """Email is a redundant notification channel — its failure never affects the
    run's exit code or the archived .md/.html files, which remain the source of truth.
    """
    if not should_notify(report):
        print("email: clean run, nothing to notify.", file=sys.stderr)
        return
    try:
        config = EmailConfig()  # type: ignore[call-arg]  # loaded from env/.env
    except ValidationError as exc:
        missing = ", ".join(str(e["loc"][0]) for e in exc.errors())
        print(
            f"email: --email requested but SMTP config incomplete (missing: {missing}). "
            "Set SMTP_USER, SMTP_PASSWORD, EMAIL_TO in .env — see .env.example.",
            file=sys.stderr,
        )
        return
    try:
        send_message(build_message(report, html_body, config), config)
        print(f"email: sent to {config.email_to}", file=sys.stderr)
    except (smtplib.SMTPException, OSError) as exc:
        print(f"email: send failed ({type(exc).__name__}: {exc})", file=sys.stderr)


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

    html_body: str | None = None
    if args.format == "html" or args.html_out or args.email:
        html_body = render_html(report)

    if args.format == "json":
        print(report.model_dump_json(indent=2))
    elif args.format == "html":
        print(html_body)
    else:
        print(render_markdown(report))

    if args.html_out:
        html_path = Path(args.html_out)
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(html_body or render_html(report), encoding="utf-8")

    if args.email:
        _maybe_send_email(report, html_body or render_html(report))

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
    parser.add_argument(
        "--email",
        action="store_true",
        help="email the digest (SMTP config from env/.env) when there are alerts or a failure",
    )
    args = parser.parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
