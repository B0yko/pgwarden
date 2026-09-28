"""Integration tests for the admin UI (item 10) and the approval page (item 7).

A web session is created directly in the state database for a given upstream
identity (a tests-only shortcut; the login flow itself is covered by the OAuth
end-to-end test), and the cookie is sent with each request.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlsplit

import asyncpg
import pytest
import pytest_asyncio

from helpers.gateway import TEST_SESSION_SECRET, Harness, run_gateway
from pgwarden.approvals.links import approval_link
from pgwarden.config import Config
from pgwarden.identity import UpstreamIdentity, person_subject
from pgwarden.web import sessions

pytestmark = pytest.mark.pg

CAROL = UpstreamIdentity("mock-idp", "usr_carol", "carol@example.com", True)
BOB = UpstreamIdentity("mock-idp", "usr_bob", "bob@example.com", True)
GET_ROUTES = [
    "/admin/audit",
    "/admin/audit?tool=query&outcome=ok",
    "/admin/audit/export?format=jsonl",
    "/admin/audit/export?format=csv",
    "/admin/approvals",
    "/admin/people",
    "/admin/clients",
    "/admin/health",
]


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


async def _session(harness: Harness, state_dsn: str, ident: UpstreamIdentity) -> tuple[str, str]:
    conn = await asyncpg.connect(state_dsn, timeout=5)
    try:
        raw, session = await sessions.create_session(conn, ident, harness.clock.now)
    finally:
        await conn.close()
    return raw, session.csrf_token


def _cookie(raw: str) -> dict[str, str]:
    return {"Cookie": f"{sessions.SESSION_COOKIE}={raw}"}


async def _admin_views(state_dsn: str) -> int:
    conn = await asyncpg.connect(state_dsn, timeout=5)
    try:
        return int(
            await conn.fetchval(
                "SELECT count(*) FROM pgwarden.audit_log WHERE event = 'admin_view'"
            )
        )
    finally:
        await conn.close()


async def test_admin_requires_login(harness: Harness) -> None:
    async with harness.raw() as http:
        resp = await http.get("/admin/audit")
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login?next=%2Fadmin%2Faudit")


async def test_non_admin_gets_403_everywhere(harness: Harness, pg_state_dsn: str) -> None:
    raw, csrf = await _session(harness, pg_state_dsn, BOB)
    async with harness.raw() as http:
        for route in GET_ROUTES:
            resp = await http.get(route, headers=_cookie(raw))
            assert resp.status_code == 403, route
        resp = await http.post(
            "/admin/people/pw_u_dana/suspend", headers=_cookie(raw), data={"csrf": csrf}
        )
        assert resp.status_code == 403


async def test_admin_pages_render_with_strict_headers_and_are_audited(
    harness: Harness, pg_state_dsn: str
) -> None:
    raw, _ = await _session(harness, pg_state_dsn, CAROL)
    before = await _admin_views(pg_state_dsn)
    async with harness.raw() as http:
        for route in GET_ROUTES:
            resp = await http.get(route, headers=_cookie(raw))
            assert resp.status_code == 200, (route, resp.text[:200])
            if "export" not in route:
                csp = resp.headers["content-security-policy"]
                assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
                assert "script-src" not in csp
                assert resp.headers["x-frame-options"] == "DENY"
    assert await _admin_views(pg_state_dsn) == before + len(GET_ROUTES)


async def test_audit_export_formats(harness: Harness, pg_state_dsn: str) -> None:
    raw, _ = await _session(harness, pg_state_dsn, CAROL)
    async with harness.raw() as http:
        jsonl = await http.get("/admin/audit/export?format=jsonl", headers=_cookie(raw))
        csv_resp = await http.get("/admin/audit/export?format=csv", headers=_cookie(raw))
    lines = [json.loads(line) for line in jsonl.text.splitlines() if line]
    assert lines and {"seq", "hash", "event"} <= lines[0].keys()
    assert csv_resp.text.splitlines()[0].startswith("id,seq,ts")
    assert csv_resp.headers["content-type"].startswith("text/csv")


async def test_suspend_needs_csrf_and_takes_effect(harness: Harness, pg_state_dsn: str) -> None:
    raw, csrf = await _session(harness, pg_state_dsn, CAROL)
    async with harness.raw() as http:
        bad = await http.post(
            "/admin/people/pw_u_dana/suspend", headers=_cookie(raw), data={"csrf": "wrong"}
        )
        assert bad.status_code == 400
        ok = await http.post(
            "/admin/people/pw_u_dana/suspend", headers=_cookie(raw), data={"csrf": csrf}
        )
        assert ok.status_code == 303
        mcp = await http.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {harness.token(person_subject('dana'))}",
                "Accept": "application/json, text/event-stream",
            },
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        assert mcp.status_code == 401
        people = await http.get("/admin/people", headers=_cookie(raw))
        assert "suspended" in people.text
        undo = await http.post(
            "/admin/people/pw_u_dana/unsuspend", headers=_cookie(raw), data={"csrf": csrf}
        )
        assert undo.status_code == 303


async def _propose(harness: Harness) -> str:
    async with harness.client(harness.token(person_subject("bob"))) as client:
        result = await client.call_tool(
            "propose_write",
            {
                "sql": "UPDATE support_tickets SET status = $1 WHERE id = $2",
                "params": ["pending_customer", 1],
                "reason": "waiting on the customer",
                "max_rows": 1,
            },
        )
    out = dict(result.structured_content or {})
    assert out.get("state") == "pending", out
    return str(out["proposal_id"])


def _link_params(harness: Harness, proposal_id: str) -> tuple[str, dict[str, str]]:
    link = approval_link(
        harness.config.public_url, TEST_SESSION_SECRET, proposal_id, now=harness.clock.now
    )
    parts = urlsplit(link)
    return parts.path, {k: v[0] for k, v in parse_qs(parts.query).items()}


async def test_approval_page_flow(harness: Harness, pg_state_dsn: str) -> None:
    proposal_id = await _propose(harness)
    path, params = _link_params(harness, proposal_id)
    carol_raw, carol_csrf = await _session(harness, pg_state_dsn, CAROL)
    bob_raw, _ = await _session(harness, pg_state_dsn, BOB)
    async with harness.raw() as http:
        # no session: redirected to login, keeping the link
        anon = await http.get(path, params=params)
        assert anon.status_code == 303 and anon.headers["location"].startswith("/login?next=")
        # tampered signature
        bad = await http.get(path, params={**params, "sig": "0" * 64}, headers=_cookie(carol_raw))
        assert bad.status_code == 404
        # signed in but not an approver
        bob = await http.get(path, params=params, headers=_cookie(bob_raw))
        assert bob.status_code == 403
        # the approver sees the full statement and parameters
        page = await http.get(path, params=params, headers=_cookie(carol_raw))
        assert page.status_code == 200
        assert "UPDATE support_tickets SET status = $1 WHERE id = $2" in page.text
        assert "pending_customer" in page.text
        # CSRF is required
        forged = await http.post(
            path, headers=_cookie(carol_raw), data={**params, "csrf": "x", "decision": "approve"}
        )
        assert forged.status_code == 400
        approved = await http.post(
            path,
            headers=_cookie(carol_raw),
            data={**params, "csrf": carol_csrf, "decision": "approve"},
        )
        assert approved.status_code == 200 and "Approved" in approved.text
        again = await http.post(
            path,
            headers=_cookie(carol_raw),
            data={**params, "csrf": carol_csrf, "decision": "approve"},
        )
        assert again.status_code == 409  # single decision
    async with harness.client(harness.token(person_subject("bob"))) as client:
        state = dict(
            (
                await client.call_tool("get_proposal", {"proposal_id": proposal_id})
            ).structured_content
            or {}
        )
    assert state["state"] == "approved"


async def test_landing_page_lists_connect_commands_and_demo_identities(harness: Harness) -> None:
    async with harness.raw() as http:
        resp = await http.get("/")
    assert resp.status_code == 200
    assert f"claude mcp add --transport http pgwarden {harness.config.public_url}/mcp" in resp.text
    assert "alice@example.com" in resp.text and "pw_u_bob" in resp.text
    assert "script-src" not in resp.headers["content-security-policy"]


async def test_post_mcp_is_not_redirected(harness: Harness) -> None:
    async with harness.raw() as http:
        resp = await http.post("/mcp", json={})
    assert resp.status_code == 401  # auth first, never a 307 to /mcp/
