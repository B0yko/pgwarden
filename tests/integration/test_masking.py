"""Integration tests for column masking (item 6), its `apply` idempotency, and
the doctor masking / writer-subset checks (item 11 / item 7), against the demo
database and roles.

The key spec point: masking is enforced by generated ``pw_masked`` views plus
``search_path``, not by post-processing result sets. So a masked person reads
masked data through the view (even via aliases, expressions or ``row_to_json``,
because the transformation lives in the view's own SQL), while the base table
is simply denied to them; a raw-access person reads unmasked data but is still
constrained by row-level security.
"""

from __future__ import annotations

from collections.abc import Callable

import asyncpg
import pytest

from pgwarden.config import Config
from pgwarden.db.doctor import DoctorContext
from pgwarden.db.masking import (
    apply_masking,
    check_masked_view_grants,
    check_masking_invariant,
    check_writer_subset,
)

pytestmark = pytest.mark.pg


async def _connect(dsn: str) -> asyncpg.Connection:
    return await asyncpg.connect(dsn, timeout=5)


# -- behaviour as a masked person (alice: analyst bundle) -------------------


async def test_alice_reads_masked_columns_through_the_view(
    pg_demo_masking: None, pg_person_dsn: Callable[[str], str]
) -> None:
    conn = await _connect(pg_person_dsn("pw_u_alice"))
    try:
        # unqualified `customers` resolves to pw_masked.customers via search_path
        assert (await conn.fetchval("SHOW search_path")).split(",")[0].strip() == "pw_masked"
        row = await conn.fetchrow(
            "SELECT full_name, email, phone FROM customers ORDER BY id LIMIT 1"
        )
        assert row is not None
        assert row["full_name"] == row["full_name"].upper()  # initials like E.T.
        assert "." in row["full_name"] and " " not in row["full_name"]
        assert row["email"].startswith(row["email"][0]) and "***@" in row["email"]
        assert row["phone"].startswith("*")
    finally:
        await conn.close()


async def test_alice_cannot_read_the_base_table(
    pg_demo_masking: None, pg_person_dsn: Callable[[str], str]
) -> None:
    conn = await _connect(pg_person_dsn("pw_u_alice"))
    try:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.fetch("SELECT full_name FROM public.customers LIMIT 1")
    finally:
        await conn.close()


async def test_masking_is_not_bypassed_by_aliases_expressions_or_row_to_json(
    pg_demo_masking: None, pg_person_dsn: Callable[[str], str]
) -> None:
    """The transformation is in the view, so re-shaping its output stays masked."""
    conn = await _connect(pg_person_dsn("pw_u_alice"))
    try:
        # alias
        aliased = await conn.fetchval("SELECT email AS e FROM customers ORDER BY id LIMIT 1")
        assert "***@" in aliased
        # expression
        expr = await conn.fetchval("SELECT upper(email) FROM customers ORDER BY id LIMIT 1")
        assert "***@" in expr
        # whole-row / row_to_json
        j = await conn.fetchval("SELECT row_to_json(c) FROM customers c ORDER BY id LIMIT 1")
        assert "***@" in j
    finally:
        await conn.close()


async def test_alice_cannot_read_the_pseudonym_salt(
    pg_demo_masking: None, pg_person_dsn: Callable[[str], str]
) -> None:
    conn = await _connect(pg_person_dsn("pw_u_alice"))
    try:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.fetch("SELECT * FROM pw_fn.pseudonym_salt")
    finally:
        await conn.close()


# -- behaviour as a raw-access person (bob: support bundle) -----------------


async def test_bob_reads_raw_customers_but_only_his_region(
    pg_demo_masking: None, pg_person_dsn: Callable[[str], str]
) -> None:
    conn = await _connect(pg_person_dsn("pw_u_bob"))
    try:
        # raw access -> no pw_masked in search_path
        assert "pw_masked" not in (await conn.fetchval("SHOW search_path"))
        email = await conn.fetchval("SELECT email FROM customers ORDER BY id LIMIT 1")
        assert "***@" not in email and "@" in email  # unmasked
        regions = {r[0] for r in await conn.fetch("SELECT DISTINCT region FROM orders")}
        assert regions == {"EU"}  # region RLS still applies
    finally:
        await conn.close()


# -- pseudonym stability (joinability) -------------------------------------


async def test_pseudonym_is_stable_for_equal_inputs(
    pg_demo_masking: None, pg_shop_dsn: str
) -> None:
    admin = await _connect(pg_shop_dsn)
    try:
        a = await admin.fetchval("SELECT pw_fn.pseudonym('join-me@example.com')")
        b = await admin.fetchval("SELECT pw_fn.pseudonym('join-me@example.com')")
        c = await admin.fetchval("SELECT pw_fn.pseudonym('other@example.com')")
        assert a == b and a != c and a.startswith("ps_")
    finally:
        await admin.close()


# -- apply idempotency and dry-run -----------------------------------------


async def test_apply_masking_is_idempotent(
    pg_demo_masking: None, pg_shop_dsn: str, pg_demo_config: object
) -> None:
    assert isinstance(pg_demo_config, Config)
    second = await apply_masking(pg_demo_config, pg_shop_dsn, dry_run=False)
    assert not second.changed, [a.kind for a in second.actions]


async def test_dry_run_changes_nothing_and_redacts_the_salt(
    pg_shop_dsn: str, pg_demo_config: object
) -> None:
    assert isinstance(pg_demo_config, Config)
    plan = await apply_masking(pg_demo_config, pg_shop_dsn, dry_run=True)
    assert plan.dry_run
    # the salt-seed action, if present, never prints the salt value
    for action in plan.actions:
        if action.kind == "salt-seed":
            assert "redacted" in action.display_sql and "decode(" not in action.display_sql


# -- doctor masking / writer-subset checks ---------------------------------


async def test_doctor_masking_checks_pass_on_the_demo(
    pg_demo_masking: None, pg_shop_dsn: str, pg_demo_config: object
) -> None:
    assert isinstance(pg_demo_config, Config)
    admin = await _connect(pg_shop_dsn)
    try:
        ctx = DoctorContext(
            admin=admin, config=pg_demo_config, role_secret="x", target_dsn=pg_shop_dsn
        )
        for check in (check_masking_invariant, check_masked_view_grants, check_writer_subset):
            result = await check(ctx)
            assert result.status == "pass", (check.__name__, result.message)
    finally:
        await admin.close()


async def test_masking_invariant_fails_when_a_masked_role_gets_raw_access(
    pg_demo_masking: None, pg_shop_dsn: str, pg_demo_config: object
) -> None:
    assert isinstance(pg_demo_config, Config)
    admin = await _connect(pg_shop_dsn)
    try:
        await admin.execute("GRANT SELECT (email) ON public.customers TO pw_u_alice")
        ctx = DoctorContext(
            admin=admin, config=pg_demo_config, role_secret="x", target_dsn=pg_shop_dsn
        )
        result = await check_masking_invariant(ctx)
        assert result.status == "fail"
        assert "pw_u_alice" in result.message
    finally:
        await admin.execute("REVOKE SELECT (email) ON public.customers FROM pw_u_alice")
        await admin.close()


async def test_masked_view_grants_fails_on_a_stray_grant(
    pg_demo_masking: None, pg_shop_dsn: str, pg_demo_config: object
) -> None:
    assert isinstance(pg_demo_config, Config)
    admin = await _connect(pg_shop_dsn)
    try:
        await admin.execute("GRANT SELECT ON pw_masked.customers TO support")
        ctx = DoctorContext(
            admin=admin, config=pg_demo_config, role_secret="x", target_dsn=pg_shop_dsn
        )
        result = await check_masked_view_grants(ctx)
        assert result.status == "fail"
        assert "support" in result.message
    finally:
        await admin.execute("REVOKE SELECT ON pw_masked.customers FROM support")
        await admin.close()


async def test_writer_subset_fails_when_a_writer_exceeds_its_bundle(
    pg_demo_masking: None, pg_shop_dsn: str, pg_demo_config: object
) -> None:
    """Grant support_writer a SELECT column the support bundle does not have."""
    assert isinstance(pg_demo_config, Config)
    admin = await _connect(pg_shop_dsn)
    try:
        # support_writer's SELECT is meant to stay within support's; refunds is a
        # write-only target for support_writer with no SELECT for support.
        await admin.execute("GRANT SELECT (amount) ON public.refunds TO support_writer")
        ctx = DoctorContext(
            admin=admin, config=pg_demo_config, role_secret="x", target_dsn=pg_shop_dsn
        )
        result = await check_writer_subset(ctx)
        assert result.status == "fail"
        assert "support_writer" in result.message
    finally:
        await admin.execute("REVOKE SELECT (amount) ON public.refunds FROM support_writer")
        await admin.close()
