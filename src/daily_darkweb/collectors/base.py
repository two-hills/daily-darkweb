from __future__ import annotations

from typing import Any, Protocol

import httpx
from tenacity import (
    AsyncRetrying,
    RetryCallState,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from daily_darkweb.core.models import CollectResult


class Collector(Protocol):
    name: str

    async def collect(self) -> CollectResult: ...


class TransientHTTPError(Exception):
    """Retryable upstream failure (429 / 5xx)."""

    def __init__(self, status_code: int, retry_after: float | None = None) -> None:
        super().__init__(f"transient upstream status {status_code}")
        self.status_code = status_code
        self.retry_after = retry_after


_RETRYABLE = (TransientHTTPError, httpx.TimeoutException, httpx.TransportError)
_MAX_RETRY_AFTER = 30.0


def _wait(retry_state: RetryCallState) -> float:
    exc = retry_state.outcome.exception() if retry_state.outcome else None
    if isinstance(exc, TransientHTTPError) and exc.retry_after is not None:
        return min(exc.retry_after, _MAX_RETRY_AFTER)
    return wait_exponential_jitter(initial=1, max=10)(retry_state)


def _parse_retry_after(header: str | None) -> float | None:
    if header is None:
        return None
    try:
        return max(0.0, float(header))
    except ValueError:
        return None


async def fetch_json(client: httpx.AsyncClient, url: str, timeout: float) -> Any:
    """GET a JSON document with transient-only retry (429/5xx/timeouts, honoring Retry-After)."""
    async for attempt in AsyncRetrying(
        retry=retry_if_exception_type(_RETRYABLE),
        stop=stop_after_attempt(3),
        wait=_wait,
        reraise=True,
    ):
        with attempt:
            response = await client.get(url, timeout=timeout)
            if response.status_code == 429 or response.status_code >= 500:
                retry_after = _parse_retry_after(response.headers.get("Retry-After"))
                raise TransientHTTPError(response.status_code, retry_after)
            response.raise_for_status()
            return response.json()
    raise AssertionError("unreachable")  # pragma: no cover
