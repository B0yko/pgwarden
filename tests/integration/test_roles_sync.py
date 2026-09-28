"""Integration tests for `pgwarden roles sync` against the demo config and data."""

from __future__ import annotations

from collections.abc import Callable

import asyncpg
import pytest

from pgwarden.config import Config, IdentityRef, PersonConfig, person_role_name
from pgwarden.db.provisioning import sync_roles
from pgwarden.db.scram import derive_password

pytestmark = pytest.mark.pg


async def test_bob_sees_only_eu(pg_demo_roles: None, pg_person_dsn: Callable[[str], str]) -> None:
    conn = await asyncpg.connect(pg_person_dsn("pw_u_bob"), timeout=5)
    try:
        rows = await conn.fetch("SELECT DISTINCT region FROM support_tickets")
    finally:
        await conn.close()
    assert {r["region"] for r in rows} == {"EU"}


async def test_dana_sees_only_us(pg_demo_roles: None, pg_person_dsn: Callable[[str], str]) -> None:
    conn = await asyncpg.connect(pg_person_dsn("pw_u_dana"), timeout=5)
    try:
        rows = await conn.fetch("SELECT DISTINCT region FROM support_tickets")
    finally:
        await conn.close()
    assert {r["region"] for r in rows} == {"US"}


async def test_nobody_reads_billing(
    pg_demo_roles: None, pg_person_dsn: Callable[[str], str]
) -> None:
    for role in ("pw_u_alice", "pw_u_bob", "pw_u_dana"):
        conn = await asyncpg.connect(pg_person_dsn(role), timeout=5)
        try:
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await conn.fetch("SELECT 1 FROM billing.payment_methods LIMIT 1")
        finally:
            await conn.close()


async def test_analyst_cannot_read_tickets_or_raw_customers(
    pg_demo_roles: None, pg_person_dsn: Callable[[str], str]
) -> None:
    conn = await asyncpg.connect(pg_person_dsn("pw_u_alice"), timeout=5)
    try:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.fetch("SELECT 1 FROM support_tickets LIMIT 1")
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.fetch("SELECT 1 FROM customers LIMIT 1")
        rows = await conn.fetch("SELECT DISTINCT region FROM orders")
        assert {r["region"] for r in rows} == {"EU", "US", "APAC"}
    finally:
        await conn.close()


async def test_bob_set_role_writer_allowed_bundle_refused(
    pg_demo_roles: None, pg_person_dsn: Callable[[str], str]
) -> None:
    conn = await asyncpg.connect(pg_person_dsn("pw_u_bob"), timeout=5)
    try:
        await conn.execute("SET ROLE support_writer")
        await conn.execute("RESET ROLE")
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute("SET ROLE support")
    finally:
        await conn.close()


async def test_connection_limit(pg_demo_roles: None, pg_shop_dsn: str) -> None:
    conn = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        row = await conn.fetchrow("SELECT rolconnlimit FROM pg_roles WHERE rolname = 'pw_u_alice'")
    finally:
        await conn.close()
    assert row is not None
    # demo config: pool.max_size=2 (default) * max_replicas=1 (default) + 1 = 3
    assert row["rolconnlimit"] == 3


async def test_role_defaults(pg_demo_roles: None, pg_person_dsn: Callable[[str], str]) -> None:
    conn = await asyncpg.connect(pg_person_dsn("pw_u_bob"), timeout=5)
    try:
        row = await conn.fetchrow("SHOW default_transaction_read_only")
        assert row is not None
        assert row[0] == "on"
    finally:
        await conn.close()


async def test_derived_password_login_works(
    pg_demo_roles: None, pg_person_dsn: Callable[[str], str]
) -> None:
    conn = await asyncpg.connect(pg_person_dsn("pw_u_alice"), timeout=5)
    await conn.close()


async def test_masked_search_path_for_analyst_but_not_support(
    pg_demo_roles: None, pg_shop_dsn: str
) -> None:
    conn = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        rows = await conn.fetch(
            "SELECT rolname, rolconfig FROM pg_roles WHERE rolname IN ('pw_u_alice', 'pw_u_bob')"
        )
    finally:
        await conn.close()
    by_name = {r["rolname"]: r["rolconfig"] for r in rows}
    assert any("search_path=pw_masked, public" in (entry or "") for entry in by_name["pw_u_alice"])
    assert not any("search_path" in (entry or "") for entry in by_name["pw_u_bob"])


async def test_second_run_is_a_no_op(
    pg_demo_roles: None, pg_shop_dsn: str, pg_role_secret: str, pg_demo_config: object
) -> None:
    assert isinstance(pg_demo_config, Config)
    result = await sync_roles(pg_demo_config, pg_shop_dsn, pg_role_secret, dry_run=False)
    assert result.actions == []


async def test_dry_run_creates_nothing(
    pg_demo_roles: None, pg_shop_dsn: str, pg_role_secret: str, pg_demo_config: object
) -> None:
    assert isinstance(pg_demo_config, Config)
    extra = PersonConfig(
        identity=IdentityRef(email="drytest@example.com"), role="drytest", bundles=["analyst"]
    )
    modified = pg_demo_config.model_copy(update={"people": [*pg_demo_config.people, extra]})

    result = await sync_roles(modified, pg_shop_dsn, pg_role_secret, dry_run=True)
    assert result.changed

    conn = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        exists = await conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname = 'pw_u_drytest'")
    finally:
        await conn.close()
    assert exists is None


async def test_no_plaintext_password_in_generated_sql(
    pg_demo_roles: None, pg_shop_dsn: str, pg_role_secret: str, pg_demo_config: object
) -> None:
    assert isinstance(pg_demo_config, Config)
    extra = PersonConfig(
        identity=IdentityRef(email="leaktest@example.com"), role="leaktest", bundles=["analyst"]
    )
    modified = pg_demo_config.model_copy(update={"people": [*pg_demo_config.people, extra]})
    plaintext = derive_password(pg_role_secret, person_role_name("leaktest"))

    result = await sync_roles(modified, pg_shop_dsn, pg_role_secret, dry_run=True)
    assert result.changed
    for action in result.actions:
        assert plaintext not in action.sql
        assert plaintext not in action.display_sql
        if "PASSWORD" in action.sql:
            assert "<verifier redacted>" in action.display_sql


async def test_prune_revokes_and_sets_nologin_without_dropping(
    pg_shop_dsn: str, pg_role_secret: str, pg_demo_config: object
) -> None:
    assert isinstance(pg_demo_config, Config)
    extra = PersonConfig(
        identity=IdentityRef(email="prunee@example.com"), role="prunee", bundles=["analyst"]
    )
    with_extra = pg_demo_config.model_copy(update={"people": [*pg_demo_config.people, extra]})
    await sync_roles(with_extra, pg_shop_dsn, pg_role_secret, dry_run=False)

    conn = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        row = await conn.fetchrow("SELECT rolcanlogin FROM pg_roles WHERE rolname = 'pw_u_prunee'")
        assert row is not None
        assert row["rolcanlogin"] is True
    finally:
        await conn.close()

    await sync_roles(pg_demo_config, pg_shop_dsn, pg_role_secret, dry_run=False, prune=True)

    conn = await asyncpg.connect(pg_shop_dsn, timeout=5)
    try:
        row = await conn.fetchrow("SELECT rolcanlogin FROM pg_roles WHERE rolname = 'pw_u_prunee'")
        assert row is not None, "prune must not DROP the role"
        assert row["rolcanlogin"] is False
        memberships = await conn.fetch(
            "SELECT 1 FROM pg_auth_members WHERE member = 'pw_u_prunee'::regrole"
        )
        assert memberships == []
    finally:
        await conn.close()

    # a further prune run over the same state changes nothing more
    result = await sync_roles(
        pg_demo_config, pg_shop_dsn, pg_role_secret, dry_run=False, prune=True
    )
    assert not any(a.role == "pw_u_prunee" for a in result.actions)
