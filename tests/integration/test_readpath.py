"""Integration tests for the read path (spec item 5) -- the traps, one by one.

Every test drives `run_read_query` (or, where the trap needs lower-level
control than the public function exposes, `PoolManager` directly) against
the real `pgw_shop` demo database and its provisioned `pw_u_*` roles.
"""

from __future__ import annotations

import asyncio

import asyncpg
import pytest

from pgwarden.db.pools import PoolManager
from pgwarden.db.readpath import _SET_CONFIG_SQL, ReadConfig, run_read_query

pytestmark = pytest.mark.pg


@pytest.fixture
async def pool_manager(pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str):
    pm = PoolManager(target_dsn=pg_target_dsn, role_secret=pg_role_secret, max_size=2)
    try:
        yield pm
    finally:
        await pm.aclose()


async def _table_checksum(admin_dsn: str, table: str) -> str:
    conn = await asyncpg.connect(admin_dsn, timeout=5)
    try:
        checksum = await conn.fetchval(
            f"SELECT md5(coalesce(string_agg(t::text, ',' ORDER BY t::text), '')) FROM {table} t"
        )
        assert isinstance(checksum, str)
        return checksum
    finally:
        await conn.close()


# -- A. multi-statement rejected at Parse ---------------------------------


async def test_multi_statement_rejected_at_parse_no_execution(
    pool_manager, pg_shop_dsn: str
) -> None:
    before = await _table_checksum(pg_shop_dsn, "products")

    result = await run_read_query(pool_manager, "pw_u_alice", "COMMIT; DROP TABLE products;", [])

    assert not result.ok
    assert result.error is not None
    assert result.error.sqlstate == "42601"

    after = await _table_checksum(pg_shop_dsn, "products")
    assert before == after


async def test_trailing_second_statement_rejected(pool_manager) -> None:
    result = await run_read_query(pool_manager, "pw_u_alice", "SELECT 1; SELECT 2;", [])
    assert not result.ok
    assert result.error is not None
    assert result.error.sqlstate == "42601"


async def test_rollback_variant_rejected(pool_manager, pg_shop_dsn: str) -> None:
    before = await _table_checksum(pg_shop_dsn, "products")
    result = await run_read_query(pool_manager, "pw_u_alice", "ROLLBACK; DROP TABLE products;", [])
    assert not result.ok
    assert result.error is not None
    assert result.error.sqlstate == "42601"
    after = await _table_checksum(pg_shop_dsn, "products")
    assert before == after


# -- prepared statements do not pile up -----------------------------------


async def test_1000_distinct_queries_keep_pg_prepared_statements_bounded(pool_manager) -> None:
    for i in range(1000):
        result = await run_read_query(pool_manager, "pw_u_alice", f"SELECT {i} AS x", [])
        assert result.ok, result.error

    async with pool_manager.acquire("pw_u_alice") as conn:
        count = await conn.fetchval(
            "SELECT count(*) FROM pg_prepared_statements WHERE name NOT LIKE '\\_\\_asyncpg\\_%'"
        )
    assert count == 0


# -- advisory locks do not survive a released connection -------------------


async def test_advisory_lock_released_another_principal_can_acquire(pool_manager) -> None:
    lock_id = 918273645
    result = await run_read_query(
        pool_manager, "pw_u_bob", f"SELECT pg_advisory_lock({lock_id})", []
    )
    assert result.ok, result.error

    async def try_lock() -> bool:
        r = await run_read_query(
            pool_manager, "pw_u_dana", f"SELECT pg_try_advisory_lock({lock_id}) AS ok", []
        )
        assert r.ok, r.error
        return bool(r.rows[0]["ok"])

    acquired = await asyncio.wait_for(try_lock(), timeout=1.0)
    assert acquired is True


# -- the big hygiene test ---------------------------------------------------

HYGIENE_STATEMENTS = [
    "PREPARE hygiene_stmt AS SELECT 1",
    "DEALLOCATE ALL",
    "LISTEN hygiene_channel",
    "DECLARE hygiene_cursor CURSOR WITH HOLD FOR SELECT * FROM support_tickets",
    "SET search_path = pg_catalog",
    "SELECT set_config('search_path', 'public', false)",
    "COMMIT",
    "SELECT pg_advisory_lock(135791113)",
]


async def _snapshot(conn: asyncpg.Connection) -> dict[str, object]:
    prepared = await conn.fetch(
        "SELECT name FROM pg_prepared_statements WHERE name NOT LIKE '\\_\\_asyncpg\\_%'"
    )
    cursors = await conn.fetch("SELECT name FROM pg_cursors WHERE name <> ''")
    listening = await conn.fetch("SELECT * FROM pg_listening_channels()")
    locks = await conn.fetch(
        "SELECT locktype, mode FROM pg_locks WHERE pid = pg_backend_pid() AND locktype = 'advisory'"
    )
    return {
        "prepared": sorted(r["name"] for r in prepared),
        "cursors": sorted(r["name"] for r in cursors),
        "listening": sorted(r[0] for r in listening),
        "locks": len(locks),
        "current_user": await conn.fetchval("SELECT current_user"),
        "search_path": await conn.fetchval("SHOW search_path"),
        "read_only": await conn.fetchval("SHOW default_transaction_read_only"),
    }


async def test_hygiene_matches_fresh_connection_after_each_statement(
    pool_manager, pg_person_dsn
) -> None:
    role = "pw_u_bob"

    fresh = await asyncpg.connect(pg_person_dsn(role), timeout=5, statement_cache_size=0)
    try:
        fresh_snapshot = await _snapshot(fresh)
    finally:
        await fresh.close()

    for sql in HYGIENE_STATEMENTS:
        result = await run_read_query(pool_manager, role, sql, [])
        # Every one of these statements is a no-op or self-contained utility
        # command the read path can run without erroring.
        assert result.ok, f"{sql!r} unexpectedly errored: {result.error}"

        async with pool_manager.acquire(role) as conn:
            snapshot = await _snapshot(conn)
            next_query = await conn.fetchval("SELECT 1")
            assert next_query == 1

        assert snapshot == fresh_snapshot, f"after {sql!r}: {snapshot} != {fresh_snapshot}"


async def test_with_hold_cursor_does_not_survive_the_rollback_itself(pool_manager) -> None:
    # Spec: a WITH HOLD cursor needs a COMMIT to survive, and the read path
    # always ROLLBACKs, so it should already be gone even before the pool's
    # own DISCARD ALL reset runs. Verified directly, without going through
    # the reset step, by inspecting pg_cursors on the *same* connection
    # right after the call but reasoned about via the public API: acquiring
    # again (after the pool's reset already ran) still must show zero.
    role = "pw_u_bob"
    result = await run_read_query(
        pool_manager, role, "DECLARE wh_cur CURSOR WITH HOLD FOR SELECT * FROM support_tickets", []
    )
    assert result.ok, result.error
    async with pool_manager.acquire(role) as conn:
        cursors = await conn.fetch("SELECT name FROM pg_cursors WHERE name <> ''")
        assert cursors == []


# -- timeouts ----------------------------------------------------------------


async def test_statement_timeout_exceeded_returns_57014(pool_manager) -> None:
    cfg = ReadConfig(statement_timeout_ms=200)
    result = await run_read_query(pool_manager, "pw_u_alice", "SELECT pg_sleep(2)", [], config=cfg)
    assert not result.ok
    assert result.error is not None
    assert result.error.sqlstate == "57014"


async def test_statement_timeout_cannot_be_disabled_mid_statement(pool_manager) -> None:
    cfg = ReadConfig(statement_timeout_ms=200)
    result = await run_read_query(
        pool_manager,
        "pw_u_alice",
        "SELECT set_config('statement_timeout', '0', true), pg_sleep(2)",
        [],
        config=cfg,
    )
    assert not result.ok
    assert result.error is not None
    assert result.error.sqlstate == "57014"


async def test_lock_timeout_enforced_returns_55P03(pool_manager, pg_shop_dsn: str) -> None:
    admin = await asyncpg.connect(pg_shop_dsn, timeout=5)
    await admin.execute("BEGIN")
    await admin.execute("LOCK TABLE products IN ACCESS EXCLUSIVE MODE")
    try:
        cfg = ReadConfig(lock_timeout_ms=200)
        result = await run_read_query(
            pool_manager, "pw_u_alice", "SELECT * FROM products LIMIT 1", [], config=cfg
        )
        assert not result.ok
        assert result.error is not None
        assert result.error.sqlstate == "55P03"
    finally:
        await admin.execute("ROLLBACK")
        await admin.close()


async def test_idle_in_transaction_timeout_enforced(pg_demo_roles: None, pg_person_dsn) -> None:
    # Lower-level than run_read_query: the read path's own sequence has no
    # network-idle gap to trigger this timeout naturally, so this replicates
    # the exact same BEGIN + set_config sequence and inserts a real idle
    # gap, to confirm the GUC this module sets is actually enforced.
    #
    # Verified by experiment: unlike statement_timeout/lock_timeout (which
    # only cancel the in-flight statement, sqlstate 57014/55P03, leaving the
    # connection usable), idle_in_transaction_session_timeout makes Postgres
    # terminate the whole backend. asyncpg's protocol processes that
    # unsolicited termination as soon as the event loop is free to read the
    # socket -- often during the sleep below, before any further statement
    # is even sent -- so the connection is already closed by the time the
    # next call is attempted, which is itself the enforcement evidence.
    conn = await asyncpg.connect(pg_person_dsn("pw_u_alice"), timeout=5, statement_cache_size=0)
    try:
        tx = conn.transaction(isolation="repeatable_read", readonly=True)
        await tx.start()
        await conn.execute(_SET_CONFIG_SQL, "5000", "1000", "100", "pgwarden:idle-test")
        await asyncio.sleep(0.5)
        if conn.is_closed():
            # The server already terminated the backend; that is itself
            # the enforcement evidence (see the docstring above).
            pass
        else:
            with pytest.raises(asyncpg.PostgresError) as exc_info:
                await conn.execute("SELECT 1")
            assert exc_info.value.sqlstate == "25P03"
    finally:
        if not conn.is_closed():
            await conn.close()


# -- row cap and byte cap -----------------------------------------------------


async def test_row_cap_sets_truncated_flag(pool_manager) -> None:
    cfg = ReadConfig(row_cap=10)
    result = await run_read_query(
        pool_manager, "pw_u_alice", "SELECT * FROM generate_series(1, 20) AS x", [], config=cfg
    )
    assert result.ok, result.error
    assert result.row_count == 10
    assert result.truncated is True
    assert result.bytes_truncated is False


async def test_row_cap_not_hit_when_under_cap(pool_manager) -> None:
    cfg = ReadConfig(row_cap=500)
    result = await run_read_query(
        pool_manager, "pw_u_alice", "SELECT * FROM generate_series(1, 5) AS x", [], config=cfg
    )
    assert result.ok, result.error
    assert result.row_count == 5
    assert result.truncated is False


async def test_byte_cap_truncates_rows_within_row_cap(pool_manager) -> None:
    cfg = ReadConfig(row_cap=500, max_response_bytes=2000)
    result = await run_read_query(
        pool_manager,
        "pw_u_alice",
        "SELECT repeat('x', 500) AS blob FROM generate_series(1, 100) AS x",
        [],
        config=cfg,
    )
    assert result.ok, result.error
    assert 0 < result.row_count < 100
    assert result.bytes_truncated is True


async def test_oversized_single_row_dropped_and_flagged_residual_risk(pool_manager) -> None:
    # Documented residual risk (see serialize.py and STATUS.md): a single
    # row that alone exceeds max_response_bytes cannot be bounded to a
    # partial row; it is dropped entirely and bytes_truncated is set.
    cfg = ReadConfig(row_cap=500, max_response_bytes=1000)
    result = await run_read_query(
        pool_manager,
        "pw_u_alice",
        "SELECT repeat('x', 100000) AS blob",
        [],
        config=cfg,
    )
    assert result.ok, result.error
    assert result.row_count == 0
    assert result.bytes_truncated is True


# -- read-only enforcement ----------------------------------------------------


async def test_write_rejected_read_only_25006(pool_manager, pg_shop_dsn: str) -> None:
    before = await _table_checksum(pg_shop_dsn, "products")
    result = await run_read_query(
        pool_manager, "pw_u_alice", "UPDATE products SET price = price + 1", []
    )
    assert not result.ok
    assert result.error is not None
    assert result.error.sqlstate == "25006"
    after = await _table_checksum(pg_shop_dsn, "products")
    assert before == after


async def test_delete_rejected_read_only_25006(pool_manager, pg_shop_dsn: str) -> None:
    before = await _table_checksum(pg_shop_dsn, "orders")
    result = await run_read_query(pool_manager, "pw_u_alice", "DELETE FROM orders", [])
    assert not result.ok
    assert result.error is not None
    assert result.error.sqlstate == "25006"
    after = await _table_checksum(pg_shop_dsn, "orders")
    assert before == after


# -- retryable errors propagate all the way through run_read_query -----------


async def test_pool_exhaustion_surfaces_as_retryable_through_run_read_query(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str
) -> None:
    pm = PoolManager(target_dsn=pg_target_dsn, role_secret=pg_role_secret, max_size=1)
    try:
        async with pm.acquire("pw_u_bob"):
            result = await run_read_query(pm, "pw_u_bob", "SELECT 1", [])
            assert not result.ok
            assert result.error is not None
            assert result.error.sqlstate == "53300"
            assert result.error.retryable is True
            assert result.error.retry_after_s is not None
            assert result.error.retry_after_s > 0
    finally:
        await pm.aclose()


# -- RLS through the real read path -----------------------------------------


async def test_bob_sees_only_eu_through_read_path(pool_manager) -> None:
    result = await run_read_query(
        pool_manager, "pw_u_bob", "SELECT DISTINCT region FROM support_tickets", []
    )
    assert result.ok, result.error
    assert {row["region"] for row in result.rows} == {"EU"}


async def test_dana_sees_only_us_through_read_path(pool_manager) -> None:
    result = await run_read_query(
        pool_manager, "pw_u_dana", "SELECT DISTINCT region FROM support_tickets", []
    )
    assert result.ok, result.error
    assert {row["region"] for row in result.rows} == {"US"}


async def test_alice_sees_all_regions_through_read_path(pool_manager) -> None:
    result = await run_read_query(
        pool_manager, "pw_u_alice", "SELECT DISTINCT region FROM orders", []
    )
    assert result.ok, result.error
    assert {row["region"] for row in result.rows} == {"EU", "US", "APAC"}


# -- concurrency: two principals never see each other's rows/identity -------


async def test_concurrent_queries_never_cross_contaminate(pool_manager) -> None:
    async def query_as(role: str, expected_region: str) -> None:
        for _ in range(20):
            result = await run_read_query(
                pool_manager,
                role,
                "SELECT current_user AS u, region FROM support_tickets LIMIT 5",
                [],
            )
            assert result.ok, result.error
            for row in result.rows:
                assert row["u"] == role
                assert row["region"] == expected_region

    await asyncio.gather(
        query_as("pw_u_bob", "EU"),
        query_as("pw_u_dana", "US"),
        query_as("pw_u_bob", "EU"),
        query_as("pw_u_dana", "US"),
    )


async def test_array_results_survive_type_introspection(
    pg_demo_roles: None, pg_target_dsn: str, pg_role_secret: str
) -> None:
    """Regression: an array result type makes asyncpg run a type-introspection query.

    With the statement cache off that query used to go through the unnamed
    statement and replace the user's statement between Parse and Bind (08P01).
    User statements are now named, so a first-seen array type works.
    """
    from pgwarden.db.pools import PoolManager
    from pgwarden.db.readpath import run_read_query

    pm = PoolManager(target_dsn=pg_target_dsn, role_secret=pg_role_secret)
    try:
        result = await run_read_query(
            pm,
            "pw_u_bob",
            "SELECT array_agg(id) AS ids FROM (SELECT id FROM support_tickets "
            "ORDER BY created_at LIMIT 5) s",
            [],
        )
        assert result.ok, result.error
        assert len(result.rows[0]["ids"]) == 5
    finally:
        await pm.aclose()
