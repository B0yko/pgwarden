"""Integration tests for the Postgres-backed fixed-window rate limits,
including the cross-process check: the (N+1)th call is rejected even when the
calls are spread over two separate gateway connections sharing one state DB.
"""

from __future__ import annotations

import datetime as dt

import asyncpg
import pytest

from pgwarden.state.ratelimit import check_and_increment, prune_old_windows

pytestmark = pytest.mark.pg

_T0 = dt.datetime(2025, 6, 1, 12, 0, 0, tzinfo=dt.UTC)


async def test_limit_allows_up_to_n_then_rejects(pg_state_dsn: str) -> None:
    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        subject = "person:pw_u_ratelimit_a"
        for i in range(1, 61):
            r = await check_and_increment(
                conn, "query", subject, limit=60, window_seconds=60, now=_T0
            )
            assert r.allowed, (i, r)
        r = await check_and_increment(conn, "query", subject, limit=60, window_seconds=60, now=_T0)
        assert not r.allowed
        assert r.count == 61
        assert 1 <= r.retry_after_s <= 60
    finally:
        await conn.close()


async def test_next_window_resets(pg_state_dsn: str) -> None:
    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        subject = "person:pw_u_ratelimit_b"
        r1 = await check_and_increment(
            conn, "proposal", subject, limit=1, window_seconds=3600, now=_T0
        )
        assert r1.allowed
        r2 = await check_and_increment(
            conn, "proposal", subject, limit=1, window_seconds=3600, now=_T0
        )
        assert not r2.allowed
        # a later window (an hour on) is a fresh bucket
        later = _T0 + dt.timedelta(hours=1)
        r3 = await check_and_increment(
            conn, "proposal", subject, limit=1, window_seconds=3600, now=later
        )
        assert r3.allowed and r3.count == 1
    finally:
        await conn.close()


async def test_cross_process_shared_counter(pg_state_dsn: str) -> None:
    """Two separate connections (standing in for two gateway processes) share the counter."""
    conn_a = await asyncpg.connect(pg_state_dsn, timeout=5)
    conn_b = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        subject = "person:pw_u_ratelimit_c"
        allowed = 0
        for i in range(60):
            conn = conn_a if i % 2 == 0 else conn_b
            r = await check_and_increment(
                conn, "query", subject, limit=60, window_seconds=60, now=_T0
            )
            if r.allowed:
                allowed += 1
        assert allowed == 60
        # the 61st on either connection is rejected
        r = await check_and_increment(
            conn_b, "query", subject, limit=60, window_seconds=60, now=_T0
        )
        assert not r.allowed and r.count == 61
    finally:
        await conn_a.close()
        await conn_b.close()


async def test_distinct_subjects_and_scopes_are_independent(pg_state_dsn: str) -> None:
    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        a = await check_and_increment(conn, "query", "ip:one", limit=1, window_seconds=60, now=_T0)
        b = await check_and_increment(conn, "query", "ip:two", limit=1, window_seconds=60, now=_T0)
        c = await check_and_increment(
            conn, "registration", "ip:one", limit=1, window_seconds=3600, now=_T0
        )
        assert a.allowed and b.allowed and c.allowed
    finally:
        await conn.close()


async def test_prune_old_windows(pg_state_dsn: str) -> None:
    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        old = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
        await check_and_increment(
            conn, "query", "person:prune_me", limit=60, window_seconds=60, now=old
        )
        removed = await prune_old_windows(conn, older_than=dt.datetime(2021, 1, 1, tzinfo=dt.UTC))
        assert removed >= 1
    finally:
        await conn.close()
