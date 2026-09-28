"""End-to-end checks against the running compose stack: the OAuth flow through
the real mock IdP, the read path as different people, machine credentials,
approval email in Mailpit, the gateway container's secrets, and the audit chain.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess

import asyncpg
import httpx
import pytest

from helpers.stack import Stack
from pgwarden.redteam.mcp_client import call_tool
from pgwarden.redteam.stack import StackClient
from pgwarden.state.audit import verify_chain

pytestmark = pytest.mark.stack


def _client(stack: Stack) -> StackClient:
    return StackClient(stack.base_url)


def test_landing_metadata_and_no_redirect(stack: Stack) -> None:
    assert httpx.get(f"{stack.base_url}/").status_code == 200
    prm = httpx.get(f"{stack.base_url}/.well-known/oauth-protected-resource/mcp").json()
    assert prm["resource"] == f"{stack.base_url}/mcp"
    resp = httpx.post(f"{stack.base_url}/mcp", json={}, follow_redirects=False)
    assert resp.status_code == 401 and "location" not in resp.headers


def test_bob_signs_in_and_sees_eu_rows_only(stack: Stack) -> None:
    async def run() -> None:
        client = _client(stack)
        tokens = await client.login("usr_bob")
        who = await call_tool(client.resource, tokens.access_token, "whoami", {})
        assert who.result["pg_role"] == "pw_u_bob"
        rows = await call_tool(
            client.resource,
            tokens.access_token,
            "query",
            {"sql": "SELECT DISTINCT region FROM support_tickets"},
        )
        assert rows.result["rows_untrusted"] == [{"region": "EU"}]
        assert (await client.refresh(tokens)).status_code == 200

    asyncio.run(run())


def test_alice_gets_masked_pii(stack: Stack) -> None:
    async def run() -> None:
        client = _client(stack)
        tokens = await client.login("usr_alice")
        out = await call_tool(
            client.resource,
            tokens.access_token,
            "query",
            {"sql": "SELECT email FROM customers ORDER BY id LIMIT 3"},
        )
        assert all("***@" in r["email"] for r in out.result["rows_untrusted"])

    asyncio.run(run())


def test_machine_client_credentials(stack: Stack) -> None:
    async def run() -> None:
        client = _client(stack)
        tokens = await client.machine_token(
            "nightly-report", stack.machine_secret("nightly-report")
        )
        who = await call_tool(client.resource, tokens.access_token, "whoami", {})
        assert who.result["pg_role"] == "pw_m_nightly_report"

    asyncio.run(run())


def test_approval_notice_reaches_mailpit_without_sql(stack: Stack) -> None:
    async def run() -> str:
        client = _client(stack)
        tokens = await client.login("usr_bob")
        out = await call_tool(
            client.resource,
            tokens.access_token,
            "propose_write",
            {
                "sql": "UPDATE support_tickets SET status = $1 WHERE id = $2",
                "params": ["pending_customer", 1],
                "reason": "stack test",
                "max_rows": 1,
            },
        )
        assert out.result.get("state") == "pending", out.text
        return str(out.result["proposal_id"])

    proposal_id = asyncio.run(run())
    messages = []
    for _ in range(20):
        listing = httpx.get(f"{stack.mailpit_url}/api/v1/messages").json()
        messages = [m for m in listing.get("messages", []) if proposal_id in m.get("Snippet", "")]
        if messages:
            break
        asyncio.run(asyncio.sleep(0.5))
    assert messages, "no approval email arrived in Mailpit"
    full = httpx.get(f"{stack.mailpit_url}/api/v1/message/{messages[0]['ID']}").json()
    text = full.get("Text", "")
    assert f"/approve/{proposal_id}?" in text
    assert "SET status" not in text and "pending_customer" not in text


@pytest.mark.skipif(shutil.which("docker") is None, reason="needs the docker CLI")
def test_gateway_container_holds_no_admin_credentials(stack: Stack) -> None:
    name = f"{stack.project}-gateway-1"
    raw = subprocess.run(
        ["docker", "inspect", name], capture_output=True, text=True, check=True
    ).stdout
    info = json.loads(raw)[0]
    env = "\n".join(info["Config"]["Env"])
    assert "ADMIN_DSN" not in env and "POSTGRES_PASSWORD" not in env
    admin_password = stack.secret("postgres/postgres_password")
    assert admin_password not in env
    for mount in info["Mounts"]:
        assert not mount["RW"], mount
        assert mount["Source"].endswith(("/gateway", "/demo")), mount["Source"]
    exec_ls = subprocess.run(
        ["docker", "exec", name, "ls", "/run/pgwarden"], capture_output=True, text=True, check=True
    ).stdout.split()
    assert "admin_dsn" not in exec_ls and "postgres_password" not in exec_ls


def test_audit_chain_verifies(stack: Stack) -> None:
    async def run() -> None:
        conn = await asyncpg.connect(stack.state_dsn, timeout=5)
        try:
            result = await verify_chain(conn)
        finally:
            await conn.close()
        assert result.ok, result.detail

    asyncio.run(run())
