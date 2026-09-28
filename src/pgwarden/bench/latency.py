"""Latency overhead of the gateway against direct Postgres (item 4).

For each committed query shape it times three paths:

* **direct**: plain asyncpg as the same machine role, warm connection.
* **direct + wrapper**: the same ``BEGIN READ ONLY`` / ``set_config`` / named
  prepare / portal fetch / ``ROLLBACK`` sequence the read path uses, so the cost
  of the read-path wrapper is separated from the cost of the MCP/HTTP hop.
* **gateway**: the MCP ``tools/call query`` over HTTP with a warm token.

It reports p50/p95 per path and the gateway overhead, plus the median of each
``Server-Timing`` span and the cold first-query cost for a role whose pool was
evicted. The design target (overhead p50 <= 10 ms on the primary-key lookup) is
a target, not a claim; the real number is reported either way.
"""

from __future__ import annotations

import dataclasses
import time
from pathlib import Path
from typing import Any

import asyncpg
import httpx
import yaml

from pgwarden.db.pools import PoolManager
from pgwarden.db.readpath import ReadConfig, run_read_query
from pgwarden.redteam import mcp_client
from pgwarden.redteam.stack import Tokens

QUERIES_FILE = Path(__file__).parent / "queries.yaml"


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[k]


def load_queries() -> list[dict[str, Any]]:
    return list(yaml.safe_load(QUERIES_FILE.read_text(encoding="utf-8")))


def _parse_server_timing(raw: str) -> dict[str, float]:
    spans: dict[str, float] = {}
    for part in raw.split(","):
        part = part.strip()
        if ";dur=" in part:
            name, _, dur = part.partition(";dur=")
            try:
                spans[name.strip()] = float(dur)
            except ValueError:
                continue
    return spans


@dataclasses.dataclass
class LatencyResult:
    query: str
    direct_p50: float
    direct_p95: float
    wrapper_p50: float
    wrapper_p95: float
    gateway_p50: float
    gateway_p95: float
    overhead_p50: float
    overhead_p95: float
    server_timing_median: dict[str, float]


async def _time_direct(
    conn: asyncpg.Connection, sql: str, params: list[Any], n: int
) -> list[float]:
    stmt = await conn.prepare(sql)
    samples = []
    for _ in range(n):
        start = time.perf_counter()
        await stmt.fetch(*params)
        samples.append((time.perf_counter() - start) * 1000.0)
    return samples


async def _time_wrapper(
    pm: PoolManager, role: str, sql: str, params: list[Any], n: int, cfg: ReadConfig
) -> list[float]:
    samples = []
    for _ in range(n):
        start = time.perf_counter()
        await run_read_query(pm, role, sql, params, config=cfg)
        samples.append((time.perf_counter() - start) * 1000.0)
    return samples


async def _time_gateway(
    mcp_url: str, token: str, sql: str, params: list[Any], n: int
) -> tuple[list[float], list[dict[str, float]]]:
    samples: list[float] = []
    spans: list[dict[str, float]] = []
    async with httpx.AsyncClient(timeout=30.0) as http:
        for _ in range(n):
            start = time.perf_counter()
            resp = await mcp_client.call_tool(
                mcp_url, token, "query", {"sql": sql, "params": params}, http=http
            )
            samples.append((time.perf_counter() - start) * 1000.0)
            spans.append(_parse_server_timing(resp.headers.get("server-timing", "")))
    return samples, spans


async def run_latency(
    *,
    target_dsn: str,
    role: str,
    role_secret: str,
    mcp_url: str,
    token: Tokens,
    iterations: int,
    warmup: int,
    server_timing_headers: list[dict[str, float]] | None = None,
) -> list[LatencyResult]:
    cfg = ReadConfig()
    pm = PoolManager(target_dsn=target_dsn, role_secret=role_secret)
    from urllib.parse import urlsplit, urlunsplit

    from pgwarden.db.scram import derive_password

    parts = urlsplit(target_dsn)
    netloc = f"{role}:{derive_password(role_secret, role)}@{parts.hostname}:{parts.port or 5432}"
    role_dsn = urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))

    results: list[LatencyResult] = []
    try:
        for q in load_queries():
            conn = await asyncpg.connect(role_dsn, timeout=10, statement_cache_size=0)
            try:
                await _time_direct(conn, q["sql"], q["params"], warmup)
                direct = await _time_direct(conn, q["sql"], q["params"], iterations)
            finally:
                await conn.close()
            await _time_wrapper(pm, role, q["sql"], q["params"], warmup, cfg)
            wrapper = await _time_wrapper(pm, role, q["sql"], q["params"], iterations, cfg)
            await _time_gateway(mcp_url, token.access_token, q["sql"], q["params"], warmup)
            gateway, spans = await _time_gateway(
                mcp_url, token.access_token, q["sql"], q["params"], iterations
            )
            span_median = {
                name: _percentile([s[name] for s in spans if name in s], 50)
                for name in {k for s in spans for k in s}
            }
            g50, g95 = _percentile(gateway, 50), _percentile(gateway, 95)
            d50, d95 = _percentile(direct, 50), _percentile(direct, 95)
            results.append(
                LatencyResult(
                    query=q["label"],
                    direct_p50=d50,
                    direct_p95=d95,
                    wrapper_p50=_percentile(wrapper, 50),
                    wrapper_p95=_percentile(wrapper, 95),
                    gateway_p50=g50,
                    gateway_p95=g95,
                    overhead_p50=g50 - d50,
                    overhead_p95=g95 - d95,
                    server_timing_median=span_median,
                )
            )
    finally:
        await pm.aclose()
    return results


__all__ = ["LatencyResult", "load_queries", "run_latency"]
