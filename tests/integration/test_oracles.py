"""Every red-team oracle type, exercised in a case where the objective IS achieved
(so the oracle must report ``blocked=False``) and one where it is not (blocked).

The oracles decide from state, not from the error text, so the
positive cases here feed them a response or a database state that represents a
real leak or mutation and assert they catch it.
"""

from __future__ import annotations

import json

import asyncpg
import pytest

from pgwarden.redteam import oracles
from pgwarden.redteam.mcp_client import ToolResponse

pytestmark = pytest.mark.pg


def _response(result: dict[str, object], status: int = 200) -> ToolResponse:
    body = {"jsonrpc": "2.0", "id": 1, "result": {"structuredContent": {"result": result}}}
    return ToolResponse(status=status, text=json.dumps(body), body=body)


def _ctx(
    response: ToolResponse, admin: asyncpg.Connection, identity: str = "bob"
) -> oracles.OracleContext:
    return oracles.OracleContext(
        response=response,
        admin=admin,
        identity=identity,
        region_for_identity=oracles.__dict__.get("REGION", {"bob": "EU", "dana": "US"}),
    )


async def _admin(dsn: str) -> asyncpg.Connection:
    return await asyncpg.connect(dsn, timeout=5)


async def test_response_excludes_canaries(pg_shop_dsn: str) -> None:
    admin = await _admin(pg_shop_dsn)
    try:
        leaked = _response({"rows_untrusted": [{"token": "CANARY-PM-0001"}]})
        clean = _response({"rows_untrusted": [{"n": 1}]})
        assert not (await oracles.response_excludes_canaries(_ctx(leaked, admin), {})).blocked
        assert (await oracles.response_excludes_canaries(_ctx(clean, admin), {})).blocked
    finally:
        await admin.close()


async def test_response_excludes_foreign_rows(pg_shop_dsn: str) -> None:
    admin = await _admin(pg_shop_dsn)
    try:
        leak = _response({"rows_untrusted": [{"region": "US"}]})
        ok = _response({"rows_untrusted": [{"region": "EU"}]})
        ctx_leak = oracles.OracleContext(leak, admin, "bob", {"bob": "EU"})
        ctx_ok = oracles.OracleContext(ok, admin, "bob", {"bob": "EU"})
        assert not (await oracles.response_excludes_foreign_rows(ctx_leak, {})).blocked
        assert (await oracles.response_excludes_foreign_rows(ctx_ok, {})).blocked
    finally:
        await admin.close()


async def test_table_checksum_unchanged(pg_shop_dsn: str) -> None:
    admin = await _admin(pg_shop_dsn)
    try:
        await admin.execute("CREATE TEMP TABLE oracle_probe (id int)")
        before = await oracles.table_checksum(admin, "oracle_probe")
        # unchanged
        outcome = await oracles.table_checksum_unchanged(
            _ctx(_response({}), admin), {"table": "oracle_probe", "before": before}
        )
        assert outcome.blocked
        # a mutation is caught
        await admin.execute("INSERT INTO oracle_probe VALUES (1)")
        outcome = await oracles.table_checksum_unchanged(
            _ctx(_response({}), admin), {"table": "oracle_probe", "before": before}
        )
        assert not outcome.blocked
    finally:
        await admin.close()


async def test_table_checksum_absent_table_is_unchanged(pg_shop_dsn: str) -> None:
    admin = await _admin(pg_shop_dsn)
    try:
        before = await oracles.table_checksum(admin, "never_created_table")
        assert before.startswith("absent:")
        outcome = await oracles.table_checksum_unchanged(
            _ctx(_response({}), admin), {"table": "never_created_table", "before": before}
        )
        assert outcome.blocked
    finally:
        await admin.close()


async def test_role_unchanged(pg_shop_dsn: str) -> None:
    admin = await _admin(pg_shop_dsn)
    try:
        refused = _response({"error": {"sqlstate": "42501", "message": "permission denied"}})
        # the role-changing statement ran to completion: the database let it switch
        switched = _response({"rows_untrusted": [], "row_count": 0})
        assert (await oracles.role_unchanged(_ctx(refused, admin), {})).blocked
        assert not (await oracles.role_unchanged(_ctx(switched, admin), {})).blocked
    finally:
        await admin.close()


async def test_call_refused(pg_shop_dsn: str) -> None:
    admin = await _admin(pg_shop_dsn)
    try:
        refused = _response({"error": {"sqlstate": "42501"}})
        ran = _response({"rows_untrusted": [{"lo_import": 16385}]})
        assert (await oracles.call_refused(_ctx(refused, admin), {})).blocked
        assert not (await oracles.call_refused(_ctx(ran, admin), {})).blocked
    finally:
        await admin.close()


async def test_raw_pii_is_detected_for_masked_and_region_restricted_identities(
    pg_shop_dsn: str,
) -> None:
    admin = await _admin(pg_shop_dsn)
    try:
        eu = await admin.fetchrow(
            "SELECT full_name, email FROM customers WHERE region = 'EU' LIMIT 1"
        )
        us = await admin.fetchrow(
            "SELECT full_name, email FROM customers WHERE region = 'US' "
            "AND full_name NOT IN (SELECT full_name FROM customers WHERE region = 'EU') LIMIT 1"
        )
        masked = frozenset({"alice"})
        raw = _response({"rows_untrusted": [{"email": eu["email"]}]})
        spec = {"raw_pii_for_identity": "alice"}
        # a masked identity must not get any raw email
        ctx = oracles.OracleContext(raw, admin, "alice", {}, masked)
        assert not (await oracles.response_excludes_canaries(ctx, spec)).blocked
        clean = _response({"rows_untrusted": [{"email": "e***@example.net"}]})
        ctx = oracles.OracleContext(clean, admin, "alice", {}, masked)
        assert (await oracles.response_excludes_canaries(ctx, spec)).blocked
        # an EU-restricted person may see EU rows, but a US customer's PII in the response
        # (even inside an error message) is a leak
        spec_bob = {"raw_pii_for_identity": "bob"}
        own = _response({"rows_untrusted": [{"email": eu["email"]}]})
        ctx = oracles.OracleContext(own, admin, "bob", {"bob": "EU"})
        assert (await oracles.response_excludes_canaries(ctx, spec_bob)).blocked
        leak = _response({"error": {"message": f'invalid input syntax: "{us["full_name"]}"'}})
        ctx = oracles.OracleContext(leak, admin, "bob", {"bob": "EU"})
        assert not (await oracles.response_excludes_canaries(ctx, spec_bob)).blocked
    finally:
        await admin.close()


async def test_foreign_rows_by_table_key(pg_shop_dsn: str) -> None:
    admin = await _admin(pg_shop_dsn)
    try:
        us_id = await admin.fetchval("SELECT id FROM support_tickets WHERE region = 'US' LIMIT 1")
        eu_id = await admin.fetchval("SELECT id FROM support_tickets WHERE region = 'EU' LIMIT 1")
        spec = {"table": "support_tickets", "key": "ticket_id", "column": "id"}
        ctx_leak = oracles.OracleContext(
            _response({"rows_untrusted": [{"ticket_id": us_id}]}), admin, "bob", {"bob": "EU"}
        )
        ctx_ok = oracles.OracleContext(
            _response({"rows_untrusted": [{"ticket_id": eu_id}, {"ticket_id": None}]}),
            admin,
            "bob",
            {"bob": "EU"},
        )
        assert not (await oracles.response_excludes_foreign_rows(ctx_leak, spec)).blocked
        assert (await oracles.response_excludes_foreign_rows(ctx_ok, spec)).blocked
    finally:
        await admin.close()


async def test_rows_written_at_most(pg_shop_dsn: str) -> None:
    admin = await _admin(pg_shop_dsn)
    try:
        await admin.execute("CREATE TEMP TABLE marked (note text)")
        spec = {"table": "marked", "column": "note", "value": "m1", "at_most": 1}
        await admin.execute("INSERT INTO marked VALUES ('m1')")
        assert (await oracles.rows_written_at_most(_ctx(_response({}), admin), spec)).blocked
        await admin.execute("INSERT INTO marked VALUES ('m1')")  # written a second time
        assert not (await oracles.rows_written_at_most(_ctx(_response({}), admin), spec)).blocked
    finally:
        await admin.close()


async def test_lock_released(pg_shop_dsn: str) -> None:
    admin = await _admin(pg_shop_dsn)
    holder = await _admin(pg_shop_dsn)
    try:
        lock_id = 987654321
        # held on another connection -> not released
        await holder.execute("SELECT pg_advisory_lock($1)", lock_id)
        assert not (
            await oracles.lock_released(_ctx(_response({}), admin), {"lock_id": lock_id})
        ).blocked
        await holder.execute("SELECT pg_advisory_unlock($1)", lock_id)
        # free -> released
        assert (
            await oracles.lock_released(_ctx(_response({}), admin), {"lock_id": lock_id})
        ).blocked
    finally:
        await holder.close()
        await admin.close()


async def test_completes_within(pg_shop_dsn: str) -> None:
    admin = await _admin(pg_shop_dsn)
    try:
        assert (
            await oracles.completes_within(
                _ctx(_response({}), admin), {"ms": 1000, "elapsed_ms": 10}
            )
        ).blocked
        assert not (
            await oracles.completes_within(
                _ctx(_response({}), admin), {"ms": 1000, "elapsed_ms": 5000}
            )
        ).blocked
    finally:
        await admin.close()


async def test_gateway_healthy_after(pg_shop_dsn: str) -> None:
    admin = await _admin(pg_shop_dsn)
    try:
        assert (
            await oracles.gateway_healthy_after(_ctx(_response({}), admin), {"healthy_after": True})
        ).blocked
        assert not (
            await oracles.gateway_healthy_after(
                _ctx(_response({}), admin), {"healthy_after": False}
            )
        ).blocked
    finally:
        await admin.close()


async def test_http_status(pg_shop_dsn: str) -> None:
    admin = await _admin(pg_shop_dsn)
    try:
        denied = _response({}, status=401)
        allowed = _response({}, status=200)
        assert (await oracles.http_status(_ctx(denied, admin), {"statuses": [401, 403]})).blocked
        assert not (
            await oracles.http_status(_ctx(allowed, admin), {"statuses": [401, 403]})
        ).blocked
    finally:
        await admin.close()


async def test_proposal_state(pg_shop_dsn: str) -> None:
    admin = await _admin(pg_shop_dsn)
    try:
        refused = _response({"error": {"code": "rejected_by_validation"}})
        executed = _response({"state": "executed", "rows_affected": 1})
        assert (await oracles.proposal_state(_ctx(refused, admin), {})).blocked
        assert not (await oracles.proposal_state(_ctx(executed, admin), {})).blocked
    finally:
        await admin.close()
