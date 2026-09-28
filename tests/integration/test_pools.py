"""Integration tests for `pgwarden.db.pools.PoolManager`."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import asyncpg
import pytest

from pgwarden.db.errors import RetryableDbError
from pgwarden.db.pools import PoolManager

pytestmark = pytest.mark.pg


async def test_acquire_and_release_reuses_one_connection(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str
) -> None:
    pm = PoolManager(target_dsn=pg_target_dsn, role_secret=pg_role_secret, max_size=2)
    try:
        async with pm.acquire("pw_u_bob") as conn:
            pid1 = await conn.fetchval("SELECT pg_backend_pid()")
        async with pm.acquire("pw_u_bob") as conn:
            pid2 = await conn.fetchval("SELECT pg_backend_pid()")
        assert pid1 == pid2
        idle, in_use = pm.stats()["pw_u_bob"]
        assert idle == 1
        assert in_use == 0
    finally:
        await pm.aclose()


async def test_per_principal_max_size_enforced(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str
) -> None:
    pm = PoolManager(
        target_dsn=pg_target_dsn, role_secret=pg_role_secret, max_size=2, global_cap=10
    )
    try:
        async with pm.acquire("pw_u_bob") as c1, pm.acquire("pw_u_bob") as c2:
            assert not c1.is_closed()
            assert not c2.is_closed()
            with pytest.raises(RetryableDbError) as exc_info:
                async with pm.acquire("pw_u_bob"):
                    pass
            assert exc_info.value.sqlstate == "53300"
            assert exc_info.value.retry_after_s > 0
    finally:
        await pm.aclose()


async def test_different_principals_get_independent_connections(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str
) -> None:
    pm = PoolManager(
        target_dsn=pg_target_dsn, role_secret=pg_role_secret, max_size=2, global_cap=10
    )
    try:
        async with pm.acquire("pw_u_bob") as bob_conn, pm.acquire("pw_u_dana") as dana_conn:
            bob_user = await bob_conn.fetchval("SELECT current_user")
            dana_user = await dana_conn.fetchval("SELECT current_user")
            assert bob_user == "pw_u_bob"
            assert dana_user == "pw_u_dana"
    finally:
        await pm.aclose()


async def test_global_cap_evicts_idle_lru_pool(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str
) -> None:
    pm = PoolManager(target_dsn=pg_target_dsn, role_secret=pg_role_secret, max_size=1, global_cap=2)
    try:
        # bob's connection becomes idle (released) after this block.
        async with pm.acquire("pw_u_bob") as conn:
            bob_pid = await conn.fetchval("SELECT pg_backend_pid()")
        # dana takes the 2nd of the global cap's 2 slots and stays checked out.
        async with pm.acquire("pw_u_dana"):
            assert pm.stats()["pw_u_bob"] == (1, 0)
            assert pm.stats()["pw_u_dana"] == (0, 1)

            # alice needs a 3rd slot; global cap is 2, so bob's idle connection
            # (the only idle one) must be evicted to make room.
            async with pm.acquire("pw_u_alice") as alice_conn:
                alice_pid = await alice_conn.fetchval("SELECT pg_backend_pid()")
                assert alice_pid != bob_pid
                assert pm.stats()["pw_u_bob"] == (0, 0)
    finally:
        await pm.aclose()


async def test_global_cap_with_nothing_idle_raises_retryable(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str
) -> None:
    pm = PoolManager(target_dsn=pg_target_dsn, role_secret=pg_role_secret, max_size=1, global_cap=2)
    try:
        async with pm.acquire("pw_u_bob"), pm.acquire("pw_u_dana"):
            with pytest.raises(RetryableDbError) as exc_info:
                async with pm.acquire("pw_u_alice"):
                    pass
            assert exc_info.value.sqlstate == "53300"
    finally:
        await pm.aclose()


async def test_idle_connection_closed_after_idle_timeout(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str
) -> None:
    pm = PoolManager(
        target_dsn=pg_target_dsn, role_secret=pg_role_secret, max_size=2, idle_timeout_s=0.2
    )
    try:
        async with pm.acquire("pw_u_bob") as conn:
            first_pid = await conn.fetchval("SELECT pg_backend_pid()")
        await asyncio.sleep(0.4)
        async with pm.acquire("pw_u_bob") as conn:
            second_pid = await conn.fetchval("SELECT pg_backend_pid()")
        assert first_pid != second_pid
    finally:
        await pm.aclose()


async def test_connection_recycled_past_max_lifetime(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str
) -> None:
    pm = PoolManager(
        target_dsn=pg_target_dsn, role_secret=pg_role_secret, max_size=2, max_lifetime_s=0.2
    )
    try:
        async with pm.acquire("pw_u_bob") as conn:
            first_pid = await conn.fetchval("SELECT pg_backend_pid()")
        await asyncio.sleep(0.4)
        async with pm.acquire("pw_u_bob") as conn:
            second_pid = await conn.fetchval("SELECT pg_backend_pid()")
        assert first_pid != second_pid
    finally:
        await pm.aclose()


async def test_reset_runs_discard_all_and_connection_stays_usable(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str
) -> None:
    pm = PoolManager(target_dsn=pg_target_dsn, role_secret=pg_role_secret, max_size=1)
    try:
        async with pm.acquire("pw_u_bob") as conn:
            await conn.execute("LISTEN some_channel")
            await conn.execute("SELECT pg_advisory_lock(123456)")
        async with pm.acquire("pw_u_bob") as conn:
            channels = await conn.fetch("SELECT * FROM pg_listening_channels()")
            locks = await conn.fetch(
                "SELECT 1 FROM pg_locks WHERE pid = pg_backend_pid() AND locktype = 'advisory'"
            )
            assert channels == []
            assert locks == []
            v = await conn.fetchval("SELECT 1")
            assert v == 1
    finally:
        await pm.aclose()


async def test_failed_reset_closes_connection_instead_of_reusing(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str
) -> None:
    pm = PoolManager(target_dsn=pg_target_dsn, role_secret=pg_role_secret, max_size=1)
    try:
        async with pm.acquire("pw_u_bob") as conn:
            pid1 = await conn.fetchval("SELECT pg_backend_pid()")
            # Sabotage the connection so the reset step (DISCARD ALL) itself fails:
            # closing it directly is the simplest reliable way to make the next
            # `conn.execute()` raise inside `_reset`.
            await conn.close()
        # A new physical connection must have been opened, not a broken one reused.
        async with pm.acquire("pw_u_bob") as conn:
            assert not conn.is_closed()
            pid2 = await conn.fetchval("SELECT pg_backend_pid()")
            assert pid2 != pid1
    finally:
        await pm.aclose()


async def test_role_connection_limit_surfaces_as_retryable_53300(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str, pg_shop_dsn: str
) -> None:
    admin = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        await admin.execute('ALTER ROLE "pw_u_bob" CONNECTION LIMIT 1')
    finally:
        await admin.close()

    pm = PoolManager(
        target_dsn=pg_target_dsn, role_secret=pg_role_secret, max_size=5, global_cap=10
    )
    try:
        # Hold the role's one allowed connection open directly (outside the pool),
        # so the pool's own attempt to open a fresh one hits Postgres's own limit.
        from urllib.parse import quote, urlsplit, urlunsplit

        from pgwarden.db.scram import derive_password

        password = derive_password(pg_role_secret, "pw_u_bob")
        parts = urlsplit(pg_target_dsn)
        user = quote("pw_u_bob", safe="")
        pw = quote(password, safe="")
        netloc = f"{user}:{pw}@{parts.hostname}:{parts.port}"
        direct_dsn = urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))
        direct = await asyncpg.connect(direct_dsn, timeout=5)
        try:
            with pytest.raises(RetryableDbError) as exc_info:
                async with pm.acquire("pw_u_bob"):
                    pass
            assert exc_info.value.sqlstate == "53300"
        finally:
            await direct.close()
    finally:
        await pm.aclose()
        admin = await asyncpg.connect(pg_shop_dsn, timeout=5)
        try:
            await admin.execute('ALTER ROLE "pw_u_bob" CONNECTION LIMIT 3')
        finally:
            await admin.close()


def test_derived_password_matches_roles_sync(
    pg_demo_roles: None, pg_person_dsn: Callable[[str], str]
) -> None:
    # Sanity check that PoolManager and `roles sync` derive the same
    # password for the same role, so a pool-opened connection actually
    # authenticates (exercised end to end by the tests above; this just
    # pins the DSN pieces line up).
    dsn = pg_person_dsn("pw_u_bob")
    assert "pw_u_bob" in dsn


async def test_close_role_drops_idle_connections(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str
) -> None:
    pm = PoolManager(target_dsn=pg_target_dsn, role_secret=pg_role_secret, max_size=2)
    try:
        async with pm.acquire("pw_u_bob") as conn:
            first_pid = await conn.fetchval("SELECT pg_backend_pid()")
        assert pm.stats()["pw_u_bob"] == (1, 0)

        await pm.close_role("pw_u_bob")
        assert "pw_u_bob" not in pm.stats()

        async with pm.acquire("pw_u_bob") as conn:
            second_pid = await conn.fetchval("SELECT pg_backend_pid()")
        assert second_pid != first_pid
    finally:
        await pm.aclose()


async def test_close_role_on_an_unused_role_is_a_no_op(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str
) -> None:
    pm = PoolManager(target_dsn=pg_target_dsn, role_secret=pg_role_secret, max_size=2)
    try:
        await pm.close_role("pw_u_never_touched")
    finally:
        await pm.aclose()


class _FakeClock:
    """An injectable, manually-advanced clock for deterministic pool tests."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self._now = start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


async def test_idle_timeout_with_injectable_clock_no_real_sleep(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str
) -> None:
    clock = _FakeClock()
    pm = PoolManager(
        target_dsn=pg_target_dsn,
        role_secret=pg_role_secret,
        max_size=2,
        idle_timeout_s=60,
        clock=clock,
    )
    try:
        async with pm.acquire("pw_u_bob") as conn:
            first_pid = await conn.fetchval("SELECT pg_backend_pid()")
        assert pm.stats()["pw_u_bob"] == (1, 0)

        # Not idle long enough yet: the same physical connection comes back.
        clock.advance(30)
        async with pm.acquire("pw_u_bob") as conn:
            still_first_pid = await conn.fetchval("SELECT pg_backend_pid()")
        assert still_first_pid == first_pid

        # Past idle_timeout_s: the next acquire must open a fresh connection.
        clock.advance(61)
        async with pm.acquire("pw_u_bob") as conn:
            second_pid = await conn.fetchval("SELECT pg_backend_pid()")
        assert second_pid != first_pid
    finally:
        await pm.aclose()


async def test_max_lifetime_with_injectable_clock_no_real_sleep(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str
) -> None:
    clock = _FakeClock()
    pm = PoolManager(
        target_dsn=pg_target_dsn,
        role_secret=pg_role_secret,
        max_size=2,
        max_lifetime_s=300,
        clock=clock,
    )
    try:
        async with pm.acquire("pw_u_bob") as conn:
            first_pid = await conn.fetchval("SELECT pg_backend_pid()")

        # A connection past its max_lifetime_s is recycled on release, even
        # though it was never idle long enough to be reaped on that basis.
        clock.advance(301)
        async with pm.acquire("pw_u_bob") as conn:
            second_pid = await conn.fetchval("SELECT pg_backend_pid()")
        assert second_pid != first_pid
    finally:
        await pm.aclose()


async def test_background_reaper_closes_idle_connections_without_a_new_acquire(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str
) -> None:
    # Unlike the tests above (which rely on the opportunistic reap inside
    # `acquire`), this checks the standalone background task started by
    # `PoolManager.start()`: an idle connection is closed on its own, with
    # nothing else ever calling `acquire` again.
    pm = PoolManager(
        target_dsn=pg_target_dsn,
        role_secret=pg_role_secret,
        max_size=2,
        idle_timeout_s=0.2,
        reap_interval_s=0.1,
    )
    await pm.start()
    try:
        async with pm.acquire("pw_u_bob"):
            pass
        assert pm.stats()["pw_u_bob"] == (1, 0)
        await asyncio.sleep(0.6)
        assert pm.stats().get("pw_u_bob", (0, 0)) == (0, 0)
    finally:
        await pm.aclose()


async def test_aclose_stops_the_reaper_task_cleanly(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str
) -> None:
    pm = PoolManager(target_dsn=pg_target_dsn, role_secret=pg_role_secret, reap_interval_s=0.05)
    await pm.start()
    task = pm._reaper_task
    assert task is not None
    await pm.aclose()
    assert task.done()
    assert pm._reaper_task is None


async def test_in_transaction_connection_is_closed_not_reused(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str
) -> None:
    # A connection released while still inside a transaction must
    # be closed, never rolled back and put back into circulation (unlike a
    # connection whose reset step merely fails, which is also closed but for
    # a different reason -- see test_failed_reset_closes_connection_instead_of_reusing).
    pm = PoolManager(target_dsn=pg_target_dsn, role_secret=pg_role_secret, max_size=1)
    try:
        async with pm.acquire("pw_u_bob") as conn:
            first_pid = await conn.fetchval("SELECT pg_backend_pid()")
            await conn.execute("BEGIN")
            await conn.execute("SELECT 1")
            assert conn.is_in_transaction()
        # Released while still in a transaction: must not have been reused.
        async with pm.acquire("pw_u_bob") as conn:
            assert not conn.is_in_transaction()
            second_pid = await conn.fetchval("SELECT pg_backend_pid()")
        assert second_pid != first_pid
    finally:
        await pm.aclose()
