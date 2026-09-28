"""Fixed-window rate limits stored in Postgres (item 9), so they hold across
replicas.

One atomic ``INSERT ... ON CONFLICT DO UPDATE ... RETURNING`` per call bumps the
counter for the current clock-aligned window and returns the new count. A count
above the limit means the call is rejected (and the caller audits it as
``rate_limited`` and returns ``retry_after_s``). Because the increment and the
read are one statement, two gateway processes sharing this state database cannot
both slip past the limit.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import math
from typing import Literal

import asyncpg

Scope = Literal["query", "proposal", "registration"]

#: Default limits from the spec: (max_count, window_seconds).
DEFAULT_LIMITS: dict[Scope, tuple[int, int]] = {
    "query": (60, 60),
    "proposal": (10, 3600),
    "registration": (20, 3600),
}


@dataclasses.dataclass(frozen=True)
class RateResult:
    allowed: bool
    scope: Scope
    count: int
    limit: int
    retry_after_s: int


def _window_start(now: dt.datetime, window_seconds: int) -> dt.datetime:
    epoch = int(now.timestamp())
    floored = epoch - (epoch % window_seconds)
    return dt.datetime.fromtimestamp(floored, tz=dt.UTC)


async def check_and_increment(
    conn: asyncpg.Connection,
    scope: Scope,
    subject: str,
    *,
    limit: int,
    window_seconds: int,
    now: dt.datetime,
) -> RateResult:
    """Bump the current window's counter for ``(scope, subject)`` and decide.

    ``now`` is passed in (never read from the clock here) so tests can drive it
    deterministically; production callers pass ``datetime.now(timezone.utc)``.
    """
    window_start = _window_start(now, window_seconds)
    count = await conn.fetchval(
        "INSERT INTO pgwarden.rate_windows (scope, subject, window_start, count) "
        "VALUES ($1, $2, $3, 1) "
        "ON CONFLICT (scope, subject, window_start) "
        "DO UPDATE SET count = pgwarden.rate_windows.count + 1 "
        "RETURNING count",
        scope,
        subject,
        window_start,
    )
    total = int(count)
    if total <= limit:
        return RateResult(True, scope, total, limit, 0)
    window_end = window_start + dt.timedelta(seconds=window_seconds)
    retry_after_s = max(1, math.ceil((window_end - now).total_seconds()))
    return RateResult(False, scope, total, limit, retry_after_s)


async def prune_old_windows(conn: asyncpg.Connection, *, older_than: dt.datetime) -> int:
    """Delete windows that started before ``older_than``; returns rows removed.

    Optional housekeeping (fixed-window rows accumulate otherwise); safe to run
    periodically. Never touches the current window for any active subject.
    """
    result = await conn.execute(
        "DELETE FROM pgwarden.rate_windows WHERE window_start < $1", older_than
    )
    return int(result.split()[-1]) if result.startswith("DELETE") else 0


__all__ = [
    "DEFAULT_LIMITS",
    "RateResult",
    "Scope",
    "check_and_increment",
    "prune_old_windows",
]
