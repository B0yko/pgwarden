"""Cold first-query cost: connect plus SCRAM for a role whose pooled connection was evicted.

The gateway keeps one small pool per person or machine and closes a connection that
has been idle longer than ``pool.idle_timeout_s`` (60 s by default). Waiting 60 s per
sample is impractical, so this run is made against the gateway started with
``demo/pgwarden.bench-cold.yaml``, which is the bench config plus
``pool.idle_timeout_s: 1``. Each sample:

1. lists the role's backend pids (a session of the same role sees that role's other
   sessions in ``pg_stat_activity``, so no admin login is needed),
2. stays silent for ``idle_wait_s`` (longer than the idle timeout, shorter than uvicorn's
   5 s keep-alive, so the HTTP connection stays warm and only the database side is cold),
3. times one ``query`` call, then lists the pids again,
4. times a few more calls right away as the warm reference.

A sample counts as cold only if a backend pid appeared during the call, which proves a
new connection (TCP, startup, SCRAM) was opened; samples without one are excluded, and if
too few are confirmed the cold number is reported as not measured rather than guessed.
"""

from __future__ import annotations

import asyncio
import dataclasses
import sys
import time
from statistics import median
from typing import Any

import asyncpg

from pgwarden.bench.latency import _parse_server_timing, check_call, load_queries
from pgwarden.redteam import mcp_client
from pgwarden.redteam.stack import StackClient, Tokens

COLD_QUERY = "pk_lookup"
DEFAULT_IDLE_WAIT_S = 2.5
KEEPALIVE_LIMIT_S = 5.0  # uvicorn's default timeout_keep_alive
MIN_CONFIRMED_FRACTION = 0.8

_PIDS_SQL = (
    "SELECT pid FROM pg_stat_activity WHERE usename = current_user "
    "AND datname = current_database() AND pid <> pg_backend_pid()"
)


@dataclasses.dataclass
class ColdSample:
    """One evicted-pool first call and the warm calls that follow it."""

    cold_ms: float
    cold_spans: dict[str, float]
    warm_ms: list[float]
    warm_spans: list[dict[str, float]]
    fresh_backend: bool  # a new backend pid appeared while the cold call ran


def _stats(values: list[float]) -> dict[str, float]:
    return {
        "median": round(median(values), 2),
        "min": round(min(values), 2),
        "max": round(max(values), 2),
    }


def _span_medians(spans: list[dict[str, float]]) -> dict[str, float]:
    names = sorted({n for s in spans for n in s})
    return {n: round(median(s[n] for s in spans if n in s), 2) for n in names}


def summarize_cold(
    samples: list[ColdSample],
    *,
    idle_wait_s: float,
    idle_timeout_s: int | None,
    min_confirmed_fraction: float = MIN_CONFIRMED_FRACTION,
) -> dict[str, Any]:
    """Cold-start bookkeeping: keep the confirmed samples, or say it was not measured."""
    confirmed = [s for s in samples if s.fresh_backend]
    base: dict[str, Any] = {
        "query": COLD_QUERY,
        "pool_idle_timeout_s": idle_timeout_s,
        "idle_wait_s": idle_wait_s,
        "samples": len(samples),
        "confirmed_cold_samples": len(confirmed),
    }
    if not samples or len(confirmed) < min_confirmed_fraction * len(samples):
        return {
            **base,
            "measured": False,
            "reason": (
                f"only {len(confirmed)} of {len(samples)} samples opened a new database "
                "connection, so the pool was not reliably evicted between calls"
            ),
        }
    warm_all = [ms for s in confirmed for ms in s.warm_ms]
    warm_spans = [sp for s in confirmed for sp in s.warm_spans]
    cold_ms = [s.cold_ms for s in confirmed]
    cold_median = median(cold_ms)
    warm_median = median(warm_all)
    cold_spans = _span_medians([s.cold_spans for s in confirmed])
    warm_span_medians = _span_medians(warm_spans)
    return {
        **base,
        "measured": True,
        "cold_first_query_ms": _stats(cold_ms),
        "warm_query_ms": _stats(warm_all),
        "cold_cost_ms": round(cold_median - warm_median, 2),
        "db_span_cost_ms": round(cold_spans.get("db", 0.0) - warm_span_medians.get("db", 0.0), 2),
        "server_timing_median": {"cold": cold_spans, "warm": warm_span_medians},
    }


async def _backend_pids(conn: asyncpg.Connection) -> set[int]:
    return {int(r["pid"]) for r in await conn.fetch(_PIDS_SQL)}


async def _timed_query(
    client: StackClient, http: Any, token: str, sql: str, params: list[Any]
) -> tuple[float, dict[str, float]]:
    start = time.perf_counter()
    resp = await mcp_client.call_tool(
        client.mcp_endpoint, token, "query", {"sql": sql, "params": params}, http=http
    )
    elapsed = (time.perf_counter() - start) * 1000.0
    check_call(resp)
    return elapsed, _parse_server_timing(resp.headers.get("server-timing", ""))


async def run_cold(
    *,
    client: StackClient,
    token: Tokens,
    role_dsn: str,
    samples: int,
    idle_wait_s: float = DEFAULT_IDLE_WAIT_S,
    warm_calls: int = 5,
) -> list[ColdSample]:
    """Measure ``samples`` evicted-pool first calls (see the module docstring)."""
    if idle_wait_s >= KEEPALIVE_LIMIT_S:
        raise ValueError(
            f"idle_wait_s must stay below the {KEEPALIVE_LIMIT_S:g} s HTTP keep-alive, "
            "or the HTTP connection would be cold too"
        )
    query = next(q for q in load_queries() if q["name"] == COLD_QUERY)
    out: list[ColdSample] = []
    probe = await asyncpg.connect(role_dsn, timeout=10, statement_cache_size=0)
    try:
        async with client.http_client(timeout=30.0) as http:
            for _ in range(3):  # open the pool and the HTTP connection
                await _timed_query(client, http, token.access_token, query["sql"], query["params"])
            for i in range(1, samples + 1):
                before = await _backend_pids(probe)
                await asyncio.sleep(idle_wait_s)
                cold_ms, cold_spans = await _timed_query(
                    client, http, token.access_token, query["sql"], query["params"]
                )
                after = await _backend_pids(probe)
                warm: list[tuple[float, dict[str, float]]] = [
                    await _timed_query(
                        client, http, token.access_token, query["sql"], query["params"]
                    )
                    for _ in range(warm_calls)
                ]
                out.append(
                    ColdSample(
                        cold_ms=cold_ms,
                        cold_spans=cold_spans,
                        warm_ms=[w[0] for w in warm],
                        warm_spans=[w[1] for w in warm],
                        fresh_backend=bool(after - before),
                    )
                )
                print(
                    f"  cold sample {i}/{samples}: {cold_ms:.1f} ms "
                    f"(new backend: {bool(after - before)})",
                    file=sys.stderr,
                    flush=True,
                )
    finally:
        await probe.close()
    return out


__all__ = [
    "COLD_QUERY",
    "DEFAULT_IDLE_WAIT_S",
    "ColdSample",
    "run_cold",
    "summarize_cold",
]
