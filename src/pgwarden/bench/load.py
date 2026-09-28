"""Concurrent load test (item 5): many identities issuing a mix of queries.

Each virtual identity holds a warm machine token and loops for the duration,
picking a query shape by the configured mix. It reports throughput, the p50/p95/
p99 latency, the non-rate-limited error rate, and peak Postgres connections. The
gateway's own CPU/RSS are sampled from the host by the caller (the bench
container cannot see the Docker socket); this module returns the request metrics.
"""

from __future__ import annotations

import asyncio
import dataclasses
import random
import time

import asyncpg
import httpx

from pgwarden.bench.latency import _percentile, load_queries
from pgwarden.redteam import mcp_client


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
    error_rate: float
    rate_limited: int
    peak_pg_connections: int


def _pick(mix: dict[str, float], rng: random.Random) -> str:
    roll = rng.random() * sum(mix.values())
    cumulative = 0.0
    for name, weight in mix.items():
        cumulative += weight
        if roll <= cumulative:
            return name
    return next(iter(mix))


async def _sample_peak_connections(admin_dsn: str, stop: asyncio.Event, out: list[int]) -> None:
    conn = await asyncpg.connect(admin_dsn, timeout=10)
    try:
        while not stop.is_set():
            n = await conn.fetchval(
                "SELECT count(*) FROM pg_stat_activity WHERE application_name LIKE 'pgwarden:%'"
            )
            out.append(int(n))
            await asyncio.sleep(0.5)
    finally:
        await conn.close()


async def run_load(
    *,
    mcp_url: str,
    tokens: list[str],
    admin_dsn: str,
    duration_s: float,
    concurrency: int,
    mix: dict[str, float],
    seed: int = 12345,
) -> LoadResult:
    queries = {q["name"]: q for q in load_queries()}
    latencies: list[float] = []
    errors = 0
    rate_limited = 0
    deadline = time.monotonic() + duration_s
    stop = asyncio.Event()
    peak: list[int] = []
    sampler = asyncio.create_task(_sample_peak_connections(admin_dsn, stop, peak))

    async def worker(worker_id: int) -> None:
        nonlocal errors, rate_limited
        rng = random.Random(seed + worker_id)  # noqa: S311 - not cryptographic
        token = tokens[worker_id % len(tokens)]
        async with httpx.AsyncClient(timeout=30.0) as http:
            while time.monotonic() < deadline:
                q = queries[_pick(mix, rng)]
                start = time.perf_counter()
                resp = await mcp_client.call_tool(
                    mcp_url, token, "query", {"sql": q["sql"], "params": q["params"]}, http=http
                )
                latencies.append((time.perf_counter() - start) * 1000.0)
                err = resp.tool_error
                if err is not None:
                    if err.get("sqlstate") in ("53400", "53300") or err.get("retryable"):
                        rate_limited += 1
                    else:
                        errors += 1

    started = time.monotonic()
    await asyncio.gather(*(worker(i) for i in range(concurrency)))
    elapsed = time.monotonic() - started
    stop.set()
    await sampler

    total = len(latencies)
    non_rate = max(0, total - rate_limited)
    return LoadResult(
        identities=len(tokens),
        concurrency=concurrency,
        duration_s=round(elapsed, 1),
        total_requests=total,
        requests_per_s=round(total / elapsed, 1) if elapsed else 0.0,
        p50_ms=round(_percentile(latencies, 50), 2),
        p95_ms=round(_percentile(latencies, 95), 2),
        p99_ms=round(_percentile(latencies, 99), 2),
        error_rate=round(errors / non_rate, 4) if non_rate else 0.0,
        rate_limited=rate_limited,
        peak_pg_connections=max(peak) if peak else 0,
    )


def parse_mix(text: str) -> dict[str, float]:
    """Parse ``pk:60,filter:30,agg:10`` into query-name weights."""
    alias = {"pk": "pk_lookup", "filter": "filtered_select", "agg": "monthly_aggregate"}
    mix: dict[str, float] = {}
    for part in text.split(","):
        name, _, weight = part.partition(":")
        mix[alias.get(name.strip(), name.strip())] = float(weight or 1)
    return mix


__all__ = ["LoadResult", "parse_mix", "run_load"]
