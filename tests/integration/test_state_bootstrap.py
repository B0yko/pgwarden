"""Integration tests for `pgwarden db init` (pgwarden.state.bootstrap)."""

from __future__ import annotations

import asyncpg
import pytest

pytestmark = pytest.mark.pg


async def test_migrations_tracked(pg_state_dsn: str) -> None:
    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        versions = {
            r["version"] for r in await conn.fetch("SELECT version FROM pgwarden.schema_migrations")
        }
    finally:
        await conn.close()
    assert "0001_init" in versions


async def test_expected_tables_exist(pg_state_dsn: str) -> None:
    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        rows = await conn.fetch("SELECT tablename FROM pg_tables WHERE schemaname = 'pgwarden'")
    finally:
        await conn.close()
    names = {r["tablename"] for r in rows}
    assert {"schema_migrations", "identity_bindings", "people_status", "machines"} <= names


async def test_app_role_can_read_write_people_status_but_not_schema_migrations(
    pg_state_dsn: str,
) -> None:
    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        await conn.execute(
            "INSERT INTO pgwarden.people_status (person_role, suspended) VALUES ($1, false) "
            "ON CONFLICT (person_role) DO NOTHING",
            "pw_u_bootstraptest",
        )
        row = await conn.fetchrow(
            "SELECT suspended FROM pgwarden.people_status WHERE person_role = $1",
            "pw_u_bootstraptest",
        )
        assert row is not None
        assert row["suspended"] is False

        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute("INSERT INTO pgwarden.schema_migrations (version) VALUES ('hacked')")
    finally:
        await conn.close()


async def test_db_init_is_idempotent(pg_admin_dsn: str, pg_state_dsn: str) -> None:
    # pg_state_dsn already ran db_init once (session fixture); running again
    # must report and change nothing further.
    from pgwarden.state.bootstrap import db_init

    result = await db_init(pg_admin_dsn, pg_state_dsn)
    assert not result.changed
