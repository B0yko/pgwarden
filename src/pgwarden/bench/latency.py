"""Latency overhead of the gateway against direct Postgres (item 4).

For each committed query shape it times three paths:

* **direct**: plain asyncpg as the same machine role, warm connection.
* **direct + wrapper**: the same ``BEGIN READ ONLY`` / ``set_config`` / named
  prepare / portal fetch / ``ROLLBACK`` sequence the read path uses, so the cost
  of the read-path wrapper is separated from the cost of the MCP/HTTP hop.
* **gateway**: the MCP ``tools/call query`` over HTTP with a warm token.

It reports p50/p95 per path and the gateway overhead, plus the median of each
``Server-Timing`` span. A run repeats the whole measurement (``--repetitions``,
3 by default) and reports the median across repetitions with the spread (min and
max of each repetition's p50 and p95); the cold first-query cost lives in
:mod:`pgwarden.bench.cold`. The design target (overhead p50 <= 10 ms on the
primary-key lookup) is a target, not a claim; the real number is reported either
way.
"""

from __future__ import annotations

import dataclasses
import sys
import time
from collections.abc import Callable
from pathlib import Path
from statistics import median
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import yaml

from pgwarden.db.pools import PoolManager
from pgwarden.db.readpath import ReadConfig, run_read_query
from pgwarden.db.scram import derive_password
from pgwarden.redteam import mcp_client
from pgwarden.redteam.stack import StackClient, Tokens

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
    rows: int = 0  # rows the query returns, checked to be the same on every path


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


class BenchCallError(RuntimeError):
    """A timed gateway call did not return rows. A run with failing calls proves nothing."""


def check_call(resp: mcp_client.ToolResponse, expected_rows: int | None = None) -> None:
    """Raise unless the gateway answered a timed ``query`` call with the expected rows."""
    err = resp.tool_error
    if resp.status != 200 or err is not None:
        detail = err.get("message") if err else resp.text[:200]
        limit = err is not None and err.get("sqlstate") == "53400"
        hint = " (raise the limits: run the bench config)" if limit else ""
        raise BenchCallError(
            f"the gateway refused a timed call (HTTP {resp.status}): {detail}{hint}"
        )
    if expected_rows is not None and resp.result.get("row_count") != expected_rows:
        raise BenchCallError(
            f"the gateway returned {resp.result.get('row_count')} rows where the database "
            f"returns {expected_rows}: the timed paths are not running the same query"
        )


async def _time_gateway(
    client: StackClient, token: str, sql: str, params: list[Any], n: int, expected_rows: int
) -> tuple[list[float], list[dict[str, float]]]:
    samples: list[float] = []
    spans: list[dict[str, float]] = []
    async with client.http_client(timeout=30.0) as http:
        for _ in range(n):
            start = time.perf_counter()
            resp = await mcp_client.call_tool(
                client.mcp_endpoint, token, "query", {"sql": sql, "params": params}, http=http
            )
            samples.append((time.perf_counter() - start) * 1000.0)
            check_call(resp, expected_rows)
            spans.append(_parse_server_timing(resp.headers.get("server-timing", "")))
    return samples, spans


def role_dsn_for(target_dsn: str, role: str, role_secret: str) -> str:
    """A DSN that logs in as ``role`` with the password derived from the role secret."""
    parts = urlsplit(target_dsn)
    netloc = f"{role}:{derive_password(role_secret, role)}@{parts.hostname}:{parts.port or 5432}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))


async def fetch_postgres_version(role_dsn: str) -> str:
    """``SHOW server_version`` over the bench role's own login (no admin credentials)."""
    conn = await asyncpg.connect(role_dsn, timeout=10)
    try:
        return str(await conn.fetchval("SHOW server_version"))
    finally:
        await conn.close()


async def run_latency(
    *,
    target_dsn: str,
    role: str,
    role_secret: str,
    client: StackClient,
    token: Tokens,
    iterations: int,
    warmup: int,
    label: str = "",
) -> list[LatencyResult]:
    """One repetition: every committed query shape through the three paths."""
    cfg = ReadConfig()
    pm = PoolManager(target_dsn=target_dsn, role_secret=role_secret)
    role_dsn = role_dsn_for(target_dsn, role, role_secret)

    results: list[LatencyResult] = []
    try:
        for q in load_queries():
            print(f"  {label}{q['label']}", file=sys.stderr, flush=True)
            conn = await asyncpg.connect(role_dsn, timeout=10, statement_cache_size=0)
            try:
                rows = len(await conn.fetch(q["sql"], *q["params"]))
                await _time_direct(conn, q["sql"], q["params"], warmup)
                direct = await _time_direct(conn, q["sql"], q["params"], iterations)
            finally:
                await conn.close()
            await _time_wrapper(pm, role, q["sql"], q["params"], warmup, cfg)
            wrapper = await _time_wrapper(pm, role, q["sql"], q["params"], iterations, cfg)
            await _time_gateway(client, token.access_token, q["sql"], q["params"], warmup, rows)
            gateway, spans = await _time_gateway(
                client, token.access_token, q["sql"], q["params"], iterations, rows
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
                    rows=rows,
                )
            )
    finally:
        await pm.aclose()
    return results


async def run_repetitions(
    *,
    repetitions: int,
    on_repetition: Callable[[int], None] | None = None,
    **kwargs: Any,
) -> list[list[LatencyResult]]:
    """Run the whole measurement ``repetitions`` times, one after the other."""
    reps: list[list[LatencyResult]] = []
    for i in range(1, repetitions + 1):
        if on_repetition is not None:
            on_repetition(i)
        reps.append(await run_latency(label=f"[rep {i}/{repetitions}] ", **kwargs))
    return reps


# -- aggregation across repetitions -----------------------------------------------------

METRICS = (
    "direct_p50",
    "direct_p95",
    "wrapper_p50",
    "wrapper_p95",
    "gateway_p50",
    "gateway_p95",
    "overhead_p50",
    "overhead_p95",
)


def _r(value: float) -> float:
    return round(value, 2)


def aggregate_repetitions(reps: list[list[LatencyResult]]) -> list[dict[str, Any]]:
    """Median across repetitions per query, with the spread and every repetition.

    For each metric the reported value is the median of the per-repetition values;
    ``spread`` holds ``[min, max]`` of them. The overhead is the difference of the
    reported medians (via pgwarden minus direct), so the table adds up; its spread is the
    min and max of the per-repetition differences. ``server_timing_median`` is the
    median across repetitions of each repetition's per-span median.
    """
    order: list[str] = []
    by_query: dict[str, list[LatencyResult]] = {}
    for rep in reps:
        for r in rep:
            if r.query not in by_query:
                order.append(r.query)
            by_query.setdefault(r.query, []).append(r)
    rows: list[dict[str, Any]] = []
    for query in order:
        rs = by_query[query]
        row: dict[str, Any] = {"query": query}
        spread: dict[str, list[float]] = {}
        medians = {m: median(getattr(r, m) for r in rs) for m in METRICS}
        for m in METRICS:
            values = [getattr(r, m) for r in rs]
            spread[m] = [_r(min(values)), _r(max(values))]
            row[m] = _r(medians[m])
        row["overhead_p50"] = _r(medians["gateway_p50"] - medians["direct_p50"])
        row["overhead_p95"] = _r(medians["gateway_p95"] - medians["direct_p95"])
        for pct in ("p50", "p95"):
            diffs = [getattr(r, f"gateway_{pct}") - getattr(r, f"direct_{pct}") for r in rs]
            spread[f"overhead_{pct}"] = [_r(min(diffs)), _r(max(diffs))]
        row["rows"] = rs[0].rows
        row["spread"] = spread
        spans = sorted({name for r in rs for name in r.server_timing_median})
        row["server_timing_median"] = {
            name: _r(
                median(r.server_timing_median[name] for r in rs if name in r.server_timing_median)
            )
            for name in spans
        }
        row["repetition_results"] = [{m: _r(getattr(r, m)) for m in METRICS} for r in rs]
        rows.append(row)
    return rows


__all__ = [
    "BenchCallError",
    "LatencyResult",
    "aggregate_repetitions",
    "check_call",
    "fetch_postgres_version",
    "load_queries",
    "role_dsn_for",
    "run_latency",
    "run_repetitions",
]
