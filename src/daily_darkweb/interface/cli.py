from __future__ import annotations

import argparse
import asyncio
import math
import smtplib
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import httpx
from pydantic import BaseModel, Field, ValidationError

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
# Cap on gap-derived lookback growth: KEV is a small feed and max_items bounds output,
# but an unbounded window would degenerate into re-reading the whole catalog forever.
_MAX_LOOKBACK_DAYS = 365


class _State(BaseModel):
    """Contents of the state file. `last_success` is the timestamp of the last run with
    zero collector failures; date-window collectors stretch their lookback to cover the
    gap since then, so idle spells or broken runs never become silent all-clears.
    """

    seen: list[str] = Field(default_factory=list)
    last_success: datetime | None = None


def _load_state(path: Path) -> _State:
    if not path.exists():
        return _State()
    return _State.model_validate_json(path.read_text(encoding="utf-8"))


def _save_state(path: Path, previous: _State, report: Report, now: datetime) -> None:
    new_keys = [dedup_key(a.item) for a in report.alerts + report.observations]
    merged = (previous.seen + new_keys)[-_MAX_SEEN_KEYS:]
    # A failed collector means this window wasn't fully covered: keep the old timestamp
    # so the next run reaches back past the failure instead of treating it as covered.
    last_success = previous.last_success if report.has_failures else now
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        _State(seen=merged, last_success=last_success).model_dump_json(), encoding="utf-8"
    )


def _effective_recent_days(configured: int, last_success: datetime | None, now: datetime) -> int:
    """Lookback that always covers the span since the last fully-successful run, so KEV
    entries added while the pipeline wasn't running still get reported. `configured` is
    the floor; the gap-derived stretch is capped at _MAX_LOOKBACK_DAYS.
    """
    if last_success is None:
        return configured
    gap_days = math.ceil((now - last_success).total_seconds() / 86400)
    return max(configured, min(gap_days, _MAX_LOOKBACK_DAYS))


def _build_collectors(
    sources: SourcesConfig, client: httpx.AsyncClient, *, kev_since: date
) -> list[Collector]:
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
                since=kev_since,
                feed_url=sources.cisa_kev.feed_url,
                timeout_seconds=sources.cisa_kev.timeout_seconds,
                max_items=sources.cisa_kev.max_items,
            )
        )
    return collectors


def _maybe_send_email(report: Report, html_body: str) -> None:
    """Email is a redundant notification channel — its failure never affects the
    run's exit code or the archived .md/.html files, which remain the source of truth.
    """
    if not should_notify(report):
        print("email: clean run, nothing to notify.", file=sys.stderr)
        return
    try:
        config = EmailConfig()  # type: ignore[call-arg]  # loaded from env/.env/Keychain
    except ValidationError as exc:
        reasons = "; ".join(e["msg"] for e in exc.errors())
        print(f"email: --email requested but config invalid: {reasons}", file=sys.stderr)
        return
    try:
        send_message(build_message(report, html_body, config), config)
        print(f"email: sent to {config.email_to}", file=sys.stderr)
    except (smtplib.SMTPException, OSError) as exc:
        print(f"email: send failed ({type(exc).__name__}: {exc})", file=sys.stderr)


async def _run(args: argparse.Namespace, now: datetime | None = None) -> int:
    now = now or datetime.now(UTC)
    config_dir = Path(args.config_dir)
    watchlist = load_watchlist(config_dir / "watchlist.yaml")
    sources = load_sources(config_dir / "sources.yaml")

    state_path = Path(args.state)
    state = _State() if args.no_state else _load_state(state_path)

    recent_days = _effective_recent_days(sources.cisa_kev.recent_days, state.last_success, now)
    if recent_days > sources.cisa_kev.recent_days and state.last_success is not None:
        print(
            f"cisa_kev: widening lookback to {recent_days}d to cover the gap since the "
            f"last successful run ({state.last_success.date().isoformat()}).",
            file=sys.stderr,
        )
    kev_since = now.date() - timedelta(days=recent_days)

    async with httpx.AsyncClient(
        headers={"User-Agent": "daily-darkweb/0.1 (defensive CTI research)"}
    ) as client:
        collectors = _build_collectors(sources, client, kev_since=kev_since)
        if not collectors:
            print("No collectors enabled; nothing to do.", file=sys.stderr)
            return 2
        report = await run_pipeline(collectors, watchlist, frozenset(state.seen), now=now)

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
        _save_state(state_path, state, report, now)

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
