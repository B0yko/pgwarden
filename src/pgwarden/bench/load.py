"""Concurrent load test: many identities issuing a mix of queries.

Each virtual identity holds a warm machine token and loops for the duration,
picking a query shape by the configured mix. It reports throughput, the p50/p95/
p99 latency of the calls that returned rows, the error rate (rate-limited calls
excluded), and, when it has an admin DSN, the peak number of Postgres connections
held by pgwarden's roles. The bench container has no admin credentials, so in the
benchmark profile that number and the gateway's CPU and RSS are sampled from the
host by ``devtools/bench/run.sh`` while this runs.
"""

from __future__ import annotations

import asyncio
import collections
import dataclasses
import random
import time
from typing import Any

import asyncpg
import httpx

from pgwarden.bench.latency import _percentile, load_queries
from pgwarden.redteam import mcp_client
from pgwarden.redteam.stack import StackClient

# SQLSTATE the gateway answers with when a rate limit trips; anything else is an error.
RATE_LIMIT_SQLSTATE = "53400"

# Connections held by pgwarden's login roles (pw_u_*, pw_m_*) on the target database. The
# pool sets application_name only inside a transaction, so it cannot be used to count idle
# pooled connections. The host wrapper runs the same statement through psql.
PEAK_CONNECTIONS_SQL = (
    "SELECT count(*) FROM pg_stat_activity "
    "WHERE datname = current_database() AND usename LIKE 'pw\\_%'"
)


@dataclasses.dataclass
class LoadResult:
    identities: int
    concurrency: int
    duration_s: float
    total_requests: int
    requests_per_s: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    errors: int
    error_rate: float
    error_kinds: dict[str, int]
    rate_limited: int
    peak_pg_connections: int | None


def _pick(mix: dict[str, float], rng: random.Random) -> str:
    roll = rng.random() * sum(mix.values())
    cumulative = 0.0
    for name, weight in mix.items():
        cumulative += weight
        if roll <= cumulative:
            return name
    return next(iter(mix))


def classify(resp: mcp_client.ToolResponse) -> str | None:
    """``None`` for a call that returned rows, ``rate_limited``, or an error kind."""
    err = resp.tool_error
    if resp.status == 200 and err is None:
        return None
    if err is not None and err.get("sqlstate") == RATE_LIMIT_SQLSTATE:
        return "rate_limited"
    if err is not None:
        return f"sqlstate_{err.get('sqlstate') or err.get('code') or 'unknown'}"
    return f"http_{resp.status}"


async def _sample_peak_connections(admin_dsn: str, stop: asyncio.Event, out: list[int]) -> None:
    conn = await asyncpg.connect(admin_dsn, timeout=10)
    try:
        while not stop.is_set():
            out.append(int(await conn.fetchval(PEAK_CONNECTIONS_SQL)))
            await asyncio.sleep(0.5)
    finally:
        await conn.close()


def summarize_load(
    *,
    identities: int,
    concurrency: int,
    elapsed_s: float,
    latencies_ok: list[float],
    outcomes: collections.Counter[str],
    peak_connections: int | None,
) -> LoadResult:
    """Fold the raw counters of a run into the reported figures."""
    rate_limited = outcomes.get("rate_limited", 0)
    errors = sum(n for kind, n in outcomes.items() if kind != "rate_limited")
    total = len(latencies_ok) + rate_limited + errors
    non_rate = total - rate_limited
    return LoadResult(
        identities=identities,
        concurrency=concurrency,
        duration_s=round(elapsed_s, 1),
        total_requests=total,
        requests_per_s=round(total / elapsed_s, 1) if elapsed_s else 0.0,
        p50_ms=round(_percentile(latencies_ok, 50), 2),
        p95_ms=round(_percentile(latencies_ok, 95), 2),
        p99_ms=round(_percentile(latencies_ok, 99), 2),
        errors=errors,
        error_rate=round(errors / non_rate, 4) if non_rate else 0.0,
        error_kinds={k: n for k, n in sorted(outcomes.items()) if k != "rate_limited"},
        rate_limited=rate_limited,
        peak_pg_connections=peak_connections,
    )


async def run_load(
    *,
    client: StackClient,
    tokens: list[str],
    admin_dsn: str | None,
    duration_s: float,
    concurrency: int,
    mix: dict[str, float],
    seed: int = 12345,
) -> LoadResult:
    queries = {q["name"]: q for q in load_queries()}
    unknown = set(mix) - set(queries)
    if unknown:
        raise ValueError(f"unknown query shape(s) in the mix: {', '.join(sorted(unknown))}")
    latencies: list[float] = []
    outcomes: collections.Counter[str] = collections.Counter()
    deadline = time.monotonic() + duration_s
    stop = asyncio.Event()
    peak: list[int] = []
    sampler = (
        asyncio.create_task(_sample_peak_connections(admin_dsn, stop, peak)) if admin_dsn else None
    )

    async def worker(worker_id: int) -> None:
        rng = random.Random(seed + worker_id)  # noqa: S311 - not cryptographic
        token = tokens[worker_id % len(tokens)]
        async with client.http_client(timeout=30.0) as http:
            while time.monotonic() < deadline:
                q = queries[_pick(mix, rng)]
                start = time.perf_counter()
                try:
                    resp = await mcp_client.call_tool(
                        client.mcp_endpoint,
                        token,
                        "query",
                        {"sql": q["sql"], "params": q["params"]},
                        http=http,
                    )
                except httpx.HTTPError as exc:
                    outcomes[f"transport_{type(exc).__name__}"] += 1
                    continue
                elapsed = (time.perf_counter() - start) * 1000.0
                kind = classify(resp)
                if kind is None:
                    latencies.append(elapsed)
                else:
                    outcomes[kind] += 1

    started = time.monotonic()
    await asyncio.gather(*(worker(i) for i in range(concurrency)))
    elapsed = time.monotonic() - started
    stop.set()
    if sampler is not None:
        await sampler
    return summarize_load(
        identities=len(tokens),
        concurrency=concurrency,
        elapsed_s=elapsed,
        latencies_ok=latencies,
        outcomes=outcomes,
        peak_connections=max(peak) if peak else None,
    )


def parse_mix(text: str) -> dict[str, float]:
    """Parse ``pk:60,filter:30,agg:10`` into query-name weights."""
    alias = {"pk": "pk_lookup", "filter": "filtered_select", "agg": "monthly_aggregate"}
    mix: dict[str, float] = {}
    for part in text.split(","):
        name, _, weight = part.partition(":")
        mix[alias.get(name.strip(), name.strip())] = float(weight or 1)
    return mix


def result_dict(result: LoadResult) -> dict[str, Any]:
    return dataclasses.asdict(result)


__all__ = [
    "PEAK_CONNECTIONS_SQL",
    "LoadResult",
    "classify",
    "parse_mix",
    "result_dict",
    "run_load",
    "summarize_load",
]
