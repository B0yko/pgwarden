"""Every red-team oracle type, exercised in a case where the objective IS achieved
(so the oracle must report ``blocked=False``) and one where it is not (blocked).

The oracles decide from state, not from the error text (spec item 14), so the
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
        leak = _response({"rows_untrusted": [{"who": "pw_u_alice"}]})
        clean = _response({"rows_untrusted": [{"who": "pw_u_bob"}]})
        spec = {"other_roles": ["pw_u_alice"]}
        assert not (await oracles.role_unchanged(_ctx(leak, admin), spec)).blocked
        assert (await oracles.role_unchanged(_ctx(clean, admin), spec)).blocked
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
