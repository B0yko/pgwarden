"""Integration tests for the MCP gateway (item 4/5): the FastAPI app, the auth
middleware, the read-path tools, per-identity isolation, audit and Server-Timing.

The app is driven in-process over an ASGI transport with the SDK's own client,
using tokens minted by a tests-only helper (never a production flag).
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import json
import socket
import threading
import time
from collections.abc import AsyncIterator
from typing import Any

import asyncpg
import httpx2
import pytest
import pytest_asyncio
import uvicorn
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client

from pgwarden.app import Authenticator, create_app
from pgwarden.config import Config
from pgwarden.db.pools import PoolManager
from pgwarden.db.readpath import ReadConfig
from pgwarden.identity import machine_subject, person_subject
from pgwarden.mcp_server import GatewayDeps
from pgwarden.oauth.jwt import mint_access_token
from pgwarden.oauth.keys import generate_signing_key_pem, load_signing_key

pytestmark = pytest.mark.pg

_NOW = dt.datetime(2025, 6, 1, 12, 0, 0, tzinfo=dt.UTC)


def _now() -> dt.datetime:
    return _NOW


@dataclasses.dataclass
class Harness:
    base_url: str
    config: Config
    signing: Any
    audience: str

    def token(self, subject: str, *, client_id: str = "test-client") -> str:
        return mint_access_token(
            self.signing.private_key,
            self.signing.kid,
            issuer=self.config.public_url,
            audience=self.audience,
            subject=subject,
            client_id=client_id,
            now=_NOW,
        )

    def client(self, token: str | None) -> Client:
        auth = _BearerAuth(token) if token else None
        http_client = httpx2.AsyncClient(auth=auth)
        return Client(
            streamable_http_client(f"{self.base_url}/mcp", http_client=http_client), mode="auto"
        )

    def raw(self, token: str | None) -> httpx2.AsyncClient:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return httpx2.AsyncClient(base_url=self.base_url, headers=headers)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _BearerAuth(httpx2.Auth):
    def __init__(self, token: str) -> None:
        self.token = token

    def auth_flow(self, request: Any) -> Any:
        request.headers["Authorization"] = f"Bearer {self.token}"
        yield request


async def _run_gateway(
    config: Config, target_dsn: str, state_dsn: str, role_secret: str
) -> AsyncIterator[Harness]:
    signing = load_signing_key(generate_signing_key_pem())
    pool_manager = PoolManager(target_dsn=target_dsn, role_secret=role_secret)
    deps = GatewayDeps(
        config=config,
        pool_manager=pool_manager,
        state_dsn=state_dsn,
        read_config=ReadConfig(**config.read.model_dump()),
        now=_now,
    )
    audience = f"{config.public_url}/mcp"
    authenticator = Authenticator(
        config=config,
        signing_key=signing,
        issuer=config.public_url,
        audience=audience,
        now=_now,
    )
    app = create_app(deps, authenticator, server_timing=True)

    # Run the app in a real uvicorn server on its own thread/loop: the MCP
    # session manager uses anyio cancel scopes that must be entered and exited in
    # the same task, which a pytest-asyncio fixture spanning setup/teardown cannot
    # guarantee. A separate server loop sidesteps that entirely.
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 20
    async with httpx2.AsyncClient() as probe:
        while time.time() < deadline:
            with contextlib.suppress(Exception):
                if (await probe.get(f"{base_url}/healthz")).status_code == 200:
                    break
            time.sleep(0.05)
        else:  # pragma: no cover - only on a startup failure
            raise RuntimeError("gateway did not become ready")
    try:
        yield Harness(base_url=base_url, config=config, signing=signing, audience=audience)
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@pytest_asyncio.fixture
async def harness(
    pg_target_dsn: str,
    pg_state_dsn: str,
    pg_demo_masking: None,
    pg_role_secret: str,
    pg_demo_config: object,
) -> AsyncIterator[Harness]:
    assert isinstance(pg_demo_config, Config)
    async for h in _run_gateway(pg_demo_config, pg_target_dsn, pg_state_dsn, pg_role_secret):
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
    async for h in _run_gateway(limited, pg_target_dsn, pg_state_dsn, pg_role_secret):
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
