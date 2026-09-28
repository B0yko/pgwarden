"""Integration tests for the MCP gateway (item 4/5): the FastAPI app, the auth
middleware, the read-path tools, per-identity isolation, audit and Server-Timing.

The app is driven in-process over an ASGI transport with the SDK's own client,
using tokens minted by a tests-only helper (never a production flag).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import asyncpg
import pytest
import pytest_asyncio

from helpers.gateway import NOW, Harness, run_gateway
from pgwarden.config import Config
from pgwarden.identity import machine_subject, person_subject
from pgwarden.oauth.jwt import mint_access_token

pytestmark = pytest.mark.pg

_NOW = NOW


@pytest_asyncio.fixture
async def harness(
    pg_target_dsn: str,
    pg_state_dsn: str,
    pg_demo_masking: None,
    pg_role_secret: str,
    pg_demo_config: object,
) -> AsyncIterator[Harness]:
    assert isinstance(pg_demo_config, Config)
    async for h in run_gateway(pg_demo_config, pg_target_dsn, pg_state_dsn, pg_role_secret):
        yield h


@pytest_asyncio.fixture
async def low_limit_harness(
    pg_target_dsn: str,
    pg_state_dsn: str,
    pg_demo_masking: None,
    pg_role_secret: str,
    pg_demo_config: object,
) -> AsyncIterator[Harness]:
    """Same gateway, but with a queries-per-minute limit of 2, to exercise the tool path."""
    assert isinstance(pg_demo_config, Config)
    limited = pg_demo_config.model_copy(
        update={"limits": pg_demo_config.limits.model_copy(update={"queries_per_minute": 2})}
    )
    async for h in run_gateway(limited, pg_target_dsn, pg_state_dsn, pg_role_secret):
        yield h


def _structured(result: Any) -> dict[str, Any]:
    """Pull our tool's dict out of a CallToolResult (structuredContent or text)."""
    sc = getattr(result, "structured_content", None)
    if isinstance(sc, dict):
        return sc.get("result", sc) if "result" in sc and isinstance(sc["result"], dict) else sc
    content = getattr(result, "content", None)
    if content:
        return json.loads(content[0].text)  # type: ignore[union-attr]
    raise AssertionError(f"no structured content in {result!r}")


async def test_whoami_reflects_identity(harness: Harness) -> None:
    async with harness.client(harness.token(person_subject("alice"))) as client:
        result = await client.call_tool("whoami", {})
    who = _structured(result)
    assert who["subject"] == "person:alice"
    assert who["pg_role"] == "pw_u_alice"
    assert who["masking_applies"] is True
    assert "analyst" in who["bundles"]


async def test_query_as_alice_is_masked(harness: Harness) -> None:
    async with harness.client(harness.token(person_subject("alice"))) as client:
        result = await client.call_tool(
            "query", {"sql": "SELECT email FROM customers ORDER BY id LIMIT 1"}
        )
    out = _structured(result)
    assert "***@" in out["rows_untrusted"][0]["email"]
    assert out["row_count"] == 1


async def test_query_as_bob_is_raw_and_eu_only(harness: Harness) -> None:
    async with harness.client(harness.token(person_subject("bob"))) as client:
        raw = _structured(
            await client.call_tool(
                "query", {"sql": "SELECT email FROM customers ORDER BY id LIMIT 1"}
            )
        )
        regions = _structured(
            await client.call_tool("query", {"sql": "SELECT DISTINCT region FROM orders"})
        )
    assert "***@" not in raw["rows_untrusted"][0]["email"]
    assert {r["region"] for r in regions["rows_untrusted"]} == {"EU"}


async def test_two_identities_are_isolated(harness: Harness) -> None:
    async with (
        harness.client(harness.token(person_subject("alice"))) as ac,
        harness.client(harness.token(person_subject("bob"))) as bc,
    ):
        a = _structured(await ac.call_tool("whoami", {}))
        b = _structured(await bc.call_tool("whoami", {}))
    assert a["pg_role"] == "pw_u_alice"
    assert b["pg_role"] == "pw_u_bob"


async def test_multi_statement_is_rejected(harness: Harness) -> None:
    async with harness.client(harness.token(person_subject("bob"))) as client:
        out = _structured(
            await client.call_tool(
                "query", {"sql": "SELECT 1; SELECT token FROM billing.payment_methods"}
            )
        )
    assert "error" in out
    assert out["error"]["sqlstate"] == "42601"


async def test_list_tables_and_describe_table(harness: Harness) -> None:
    async with harness.client(harness.token(person_subject("bob"))) as client:
        tables = _structured(await client.call_tool("list_tables", {}))
        names = {r["table_name"] for r in tables["rows_untrusted"]}
        assert "support_tickets" in names
        desc = _structured(await client.call_tool("describe_table", {"name": "public.customers"}))
    cols = {r["column_name"] for r in desc["rows_untrusted"]}
    assert {"full_name", "email", "phone"} <= cols


async def test_machine_identity_works(harness: Harness) -> None:
    async with harness.client(harness.token(machine_subject("nightly-report"))) as client:
        who = _structured(await client.call_tool("whoami", {}))
    assert who["kind"] == "machine"
    assert who["pg_role"] == "pw_m_nightly_report"


async def test_missing_token_is_401_with_www_authenticate(harness: Harness) -> None:
    async with harness.raw(None) as http:
        resp = await http.post(
            "/mcp",
            headers={"Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
    assert resp.status_code == 401
    assert "resource_metadata=" in resp.headers.get("www-authenticate", "")


async def test_invalid_token_is_401(harness: Harness) -> None:
    async with harness.raw("not-a-jwt") as http:
        resp = await http.post(
            "/mcp",
            headers={"Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
    assert resp.status_code == 401
    assert 'error="invalid_token"' in resp.headers.get("www-authenticate", "")


async def test_unmapped_identity_is_403(harness: Harness) -> None:
    token = harness.token(person_subject("nobody"))
    async with harness.raw(token) as http:
        resp = await http.post(
            "/mcp",
            headers={"Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
    assert resp.status_code == 403


async def test_wrong_audience_token_is_rejected(harness: Harness) -> None:
    bad = mint_access_token(
        harness.signing.private_key,
        harness.signing.kid,
        issuer=harness.config.public_url,
        audience="https://someone-else.example.com/mcp",
        subject=person_subject("alice"),
        client_id="test",
        now=_NOW,
    )
    async with harness.raw(bad) as http:
        resp = await http.post(
            "/mcp",
            headers={"Accept": "application/json, text/event-stream"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
    assert resp.status_code == 401


async def test_server_timing_header_present(harness: Harness) -> None:
    async with harness.client(harness.token(person_subject("alice"))) as client:
        await client.call_tool("whoami", {})
    # a raw call to confirm the header is on the HTTP response
    token = harness.token(person_subject("alice"))
    async with harness.raw(token) as http:
        resp = await http.post(
            "/mcp",
            headers={
                "Accept": "application/json, text/event-stream",
                "Mcp-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/call",
                "Mcp-Name": "whoami",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "whoami",
                    "arguments": {},
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {},
                    },
                },
            },
        )
    assert resp.status_code == 200
    assert "server-timing" in {k.lower() for k in resp.headers}


async def test_query_is_audited(harness: Harness, pg_state_dsn: str) -> None:
    async with harness.client(harness.token(person_subject("bob"))) as client:
        await client.call_tool("query", {"sql": "SELECT 1 AS one"})
    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        row = await conn.fetchrow(
            "SELECT tool, outcome, pg_role, sql_text FROM pgwarden.audit_log "
            "WHERE tool = 'query' AND pg_role = 'pw_u_bob' ORDER BY seq DESC LIMIT 1"
        )
    finally:
        await conn.close()
    assert row is not None
    assert row["outcome"] == "ok"
    assert row["sql_text"] == "SELECT 1 AS one"


async def test_rate_limit_rejects_over_the_limit(low_limit_harness: Harness) -> None:
    # dana is queried by no other test, so her fixed-window counter starts clean.
    token = low_limit_harness.token(person_subject("dana"))
    outcomes = []
    async with low_limit_harness.client(token) as client:
        for _ in range(4):
            outcomes.append(_structured(await client.call_tool("query", {"sql": "SELECT 1"})))
    # limit is 2/minute: first two allowed, the rest rate-limited
    allowed = [o for o in outcomes if "error" not in o]
    rejected = [o for o in outcomes if "error" in o]
    assert len(allowed) == 2
    assert rejected and rejected[0]["error"]["sqlstate"] == "53400"
    assert rejected[0]["error"]["retry_after_s"] >= 1


async def test_write_tools_over_mcp(harness: Harness) -> None:
    async with harness.client(harness.token(person_subject("bob"))) as client:
        tools = {t.name for t in (await client.list_tools()).tools}
        assert {"propose_write", "get_proposal", "execute_approved_write"} <= tools
        proposed = _structured(
            await client.call_tool(
                "propose_write",
                {
                    "sql": "UPDATE support_tickets SET status = $1 WHERE id = $2",
                    "params": ["pending_customer", 1],
                    "reason": "waiting on the customer",
                    "max_rows": 1,
                },
            )
        )
        assert proposed.get("state") == "pending", proposed
        pid = proposed["proposal_id"]
        got = _structured(await client.call_tool("get_proposal", {"proposal_id": pid}))
        assert got["state"] == "pending"
        early = _structured(await client.call_tool("execute_approved_write", {"proposal_id": pid}))
        assert early["error"]["code"] == "not_executable"
        bad = _structured(
            await client.call_tool(
                "propose_write",
                {"sql": "DROP TABLE ticket_notes", "reason": "x", "max_rows": 1},
            )
        )
        assert bad["error"]["code"] == "rejected_by_validation"
    async with harness.client(harness.token(person_subject("alice"))) as client:
        denied = _structured(
            await client.call_tool(
                "propose_write",
                {"sql": "DELETE FROM orders", "reason": "x", "max_rows": 1},
            )
        )
        assert denied["error"]["code"] == "no_writer_role"
        other = _structured(await client.call_tool("get_proposal", {"proposal_id": pid}))
        assert other["error"]["code"] == "not_found"
