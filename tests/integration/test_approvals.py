"""Integration tests for the write path: validation by Postgres, the
approval lifecycle, at-most-once execution and every refusal in category H.

The service runs in the test's own event loop with a settable clock; the demo
database provides the writer role (support_writer), RLS and the refunds CHECK.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from collections.abc import AsyncIterator
from typing import Any

import asyncpg
import pytest
import pytest_asyncio

from helpers.gateway import Clock
from pgwarden.approvals.notifiers import ApprovalNotice
from pgwarden.approvals.service import ApprovalError, ApprovalService
from pgwarden.config import Config, IdentityRef
from pgwarden.db.pools import PoolManager
from pgwarden.db.readpath import ReadConfig, run_read_query
from pgwarden.identity import Principal, UpstreamIdentity, resolve_principal
from pgwarden.mcp_server import GatewayDeps

pytestmark = pytest.mark.pg

CAROL = UpstreamIdentity("mock-idp", "sub-carol", "carol@example.com", True)
BOB_LOGIN = UpstreamIdentity("mock-idp", "sub-bob", "bob@example.com", True)


class RecordingNotifier:
    name = "recording"

    def __init__(self) -> None:
        self.notices: list[ApprovalNotice] = []

    async def send(self, notice: ApprovalNotice) -> None:
        self.notices.append(notice)


class Env:
    def __init__(
        self, svc: ApprovalService, clock: Clock, recorder: RecordingNotifier, admin: str
    ) -> None:
        self.svc = svc
        self.clock = clock
        self.recorder = recorder
        self.admin_dsn = admin

    def principal(self, subject: str) -> Principal:
        p = resolve_principal(self.svc.config, subject)
        assert p is not None
        return p

    async def admin(self) -> asyncpg.Connection:
        return await asyncpg.connect(self.admin_dsn, timeout=5)


async def _make_env(
    config: Config, target_dsn: str, state_dsn: str, role_secret: str, shop_dsn: str
) -> AsyncIterator[Env]:
    clock = Clock(dt.datetime.now(tz=dt.UTC))
    pool_manager = PoolManager(target_dsn=target_dsn, role_secret=role_secret)
    state_pool = await asyncpg.create_pool(state_dsn, min_size=1, max_size=4)
    deps = GatewayDeps(
        config=config,
        pool_manager=pool_manager,
        state_dsn=state_dsn,
        read_config=ReadConfig(),
        now=clock,
        state_pool=state_pool,
    )
    recorder = RecordingNotifier()
    svc = ApprovalService(gateway=deps, session_secret="test-session-secret", notifiers=[recorder])
    try:
        yield Env(svc, clock, recorder, shop_dsn)
    finally:
        await pool_manager.aclose()
        await state_pool.close()


@pytest_asyncio.fixture
async def env(
    pg_demo_masking: None,
    pg_target_dsn: str,
    pg_state_dsn: str,
    pg_role_secret: str,
    pg_shop_dsn: str,
    pg_demo_config: object,
) -> AsyncIterator[Env]:
    assert isinstance(pg_demo_config, Config)
    # Many proposals per test run; the dedicated rate-limit test uses its own config.
    config = pg_demo_config.model_copy(
        update={"limits": pg_demo_config.limits.model_copy(update={"proposals_per_hour": 10_000})}
    )
    async for e in _make_env(config, pg_target_dsn, pg_state_dsn, pg_role_secret, pg_shop_dsn):
        yield e


async def _ticket_id(env: Env, region: str) -> int:
    conn = await env.admin()
    try:
        return int(
            await conn.fetchval(
                "SELECT id FROM support_tickets WHERE region = $1 ORDER BY id LIMIT 1", region
            )
        )
    finally:
        await conn.close()


async def _count(env: Env, sql: str, *args: Any) -> int:
    conn = await env.admin()
    try:
        return int(await conn.fetchval(sql, *args))
    finally:
        await conn.close()


async def _propose_note(
    env: Env, subject: str = "person:bob", region: str = "EU"
) -> dict[str, Any]:
    ticket = await _ticket_id(env, region)
    return await env.svc.propose(
        env.principal(subject),
        sql="INSERT INTO ticket_notes (ticket_id, region, note_body) VALUES ($1, $2, $3)",
        params=[ticket, region, "Customer called back; issue resolved."],
        reason="record the follow-up call",
        max_rows=1,
        client_id="test-client",
    )


# -- the happy path -----------------------------------------------------------------


async def test_propose_approve_execute(env: Env, pg_state_dsn: str) -> None:
    before = await _count(env, "SELECT count(*) FROM ticket_notes")
    proposal = await _propose_note(env)
    assert proposal["state"] == "pending"
    assert proposal["plan"]["operation"] == "Insert"
    assert proposal["plan"]["relation"] == "ticket_notes"

    # the notification carries a summary and a link, never SQL or parameters
    notice = env.recorder.notices[-1]
    assert notice.proposal_id == proposal["proposal_id"]
    assert "INSERT" not in notice.text().split("proposes")[0]
    assert "issue resolved" not in notice.text()

    approved = await env.svc.approve(proposal["proposal_id"], CAROL)
    assert approved["state"] == "approved"
    result = await env.svc.execute(env.principal("person:bob"), proposal["proposal_id"])
    assert result == {
        "proposal_id": proposal["proposal_id"],
        "state": "executed",
        "rows_affected": 1,
    }
    assert await _count(env, "SELECT count(*) FROM ticket_notes") == before + 1

    # every transition is audited
    conn = await asyncpg.connect(pg_state_dsn, timeout=5)
    try:
        tools = [
            (r["tool"], r["outcome"])
            for r in await conn.fetch(
                "SELECT tool, outcome FROM pgwarden.audit_log WHERE request_id = $1 ORDER BY seq",
                proposal["proposal_id"],
            )
        ]
    finally:
        await conn.close()
    assert tools == [
        ("proposal.propose", "ok"),
        ("proposal.approve", "ok"),
        ("proposal.execute", "started"),
        ("proposal.execute", "ok"),
    ]

    # and it can never run again
    with pytest.raises(ApprovalError) as exc:
        await env.svc.execute(env.principal("person:bob"), proposal["proposal_id"])
    assert exc.value.code == "not_executable"


async def test_update_status_is_accepted(env: Env) -> None:
    ticket = await _ticket_id(env, "EU")
    proposal = await env.svc.propose(
        env.principal("person:bob"),
        sql="UPDATE support_tickets SET status = $1 WHERE id = $2",
        params=["pending_customer", ticket],
        reason="waiting on the customer",
        max_rows=1,
        client_id=None,
    )
    assert proposal["plan"]["operation"] == "Update"


# -- validation by Postgres (category H SQL cases) -------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        "CREATE TABLE evil (id int)",
        "DROP TABLE ticket_notes",
        "INSERT INTO ticket_notes (ticket_id, region, note_body) VALUES (1, 'EU', 'x'); "
        "DELETE FROM ticket_notes",
        "WITH d AS (DELETE FROM ticket_notes RETURNING *) SELECT * FROM d",
        "WITH d AS (DELETE FROM ticket_notes RETURNING ticket_id, region, note_body) "
        "INSERT INTO ticket_notes (ticket_id, region, note_body) SELECT * FROM d",
        "SELECT * FROM support_tickets",
        "EXECUTE p_prepared_earlier",
        "COPY ticket_notes TO STDOUT",
        "DELETE FROM products",
        "UPDATE support_tickets SET body = 'x'",
        "TRUNCATE ticket_notes",
    ],
)
async def test_validation_rejects(env: Env, sql: str) -> None:
    with pytest.raises(ApprovalError) as exc:
        await env.svc.propose(
            env.principal("person:bob"),
            sql=sql,
            params=[],
            reason="attack",
            max_rows=1,
            client_id=None,
        )
    assert exc.value.code == "rejected_by_validation"


async def test_execute_of_statement_prepared_through_the_read_path_is_rejected(env: Env) -> None:
    bob = env.principal("person:bob")
    await run_read_query(
        env.svc.gateway.pool_manager,
        bob.role_name,
        "PREPARE p_from_read AS DELETE FROM ticket_notes",
        [],
    )
    with pytest.raises(ApprovalError) as exc:
        await env.svc.propose(
            bob, sql="EXECUTE p_from_read", params=[], reason="x", max_rows=1, client_id=None
        )
    assert exc.value.code == "rejected_by_validation"


async def test_person_without_writer_role_cannot_propose(env: Env) -> None:
    with pytest.raises(ApprovalError) as exc:
        await env.svc.propose(
            env.principal("person:alice"),
            sql="INSERT INTO ticket_notes (ticket_id, region, note_body) VALUES (1, 'EU', 'x')",
            params=[],
            reason="x",
            max_rows=1,
            client_id=None,
        )
    assert exc.value.code == "no_writer_role"


# -- approval rules ------------------------------------------------------------------


async def test_non_approver_cannot_approve(env: Env) -> None:
    proposal = await _propose_note(env)
    with pytest.raises(ApprovalError) as exc:
        await env.svc.approve(proposal["proposal_id"], BOB_LOGIN)
    assert exc.value.code == "not_an_approver"


async def test_self_approval_is_refused(
    pg_demo_masking: None,
    pg_target_dsn: str,
    pg_state_dsn: str,
    pg_role_secret: str,
    pg_shop_dsn: str,
    pg_demo_config: object,
) -> None:
    assert isinstance(pg_demo_config, Config)
    config = pg_demo_config.model_copy(
        update={
            "approvers": [*pg_demo_config.approvers, IdentityRef(email="bob@example.com")],
            "limits": pg_demo_config.limits.model_copy(update={"proposals_per_hour": 10_000}),
        }
    )
    async for e in _make_env(config, pg_target_dsn, pg_state_dsn, pg_role_secret, pg_shop_dsn):
        proposal = await _propose_note(e)
        with pytest.raises(ApprovalError) as exc:
            await e.svc.approve(proposal["proposal_id"], BOB_LOGIN)
        assert exc.value.code == "self_approval"


async def test_execute_requires_approval_and_the_proposer(env: Env) -> None:
    proposal = await _propose_note(env)
    with pytest.raises(ApprovalError) as exc:
        await env.svc.execute(env.principal("person:bob"), proposal["proposal_id"])
    assert exc.value.code == "not_executable"
    await env.svc.approve(proposal["proposal_id"], CAROL)
    with pytest.raises(ApprovalError) as exc:
        await env.svc.execute(env.principal("person:dana"), proposal["proposal_id"])
    assert exc.value.code == "not_found"


async def test_rejected_proposal_cannot_execute(env: Env) -> None:
    proposal = await _propose_note(env)
    rejected = await env.svc.reject(proposal["proposal_id"], CAROL)
    assert rejected["state"] == "rejected"
    with pytest.raises(ApprovalError):
        await env.svc.approve(proposal["proposal_id"], CAROL)
    with pytest.raises(ApprovalError):
        await env.svc.execute(env.principal("person:bob"), proposal["proposal_id"])


async def test_grant_expires_after_fifteen_minutes(env: Env) -> None:
    proposal = await _propose_note(env)
    await env.svc.approve(proposal["proposal_id"], CAROL)
    env.clock.advance(minutes=16)
    with pytest.raises(ApprovalError) as exc:
        await env.svc.execute(env.principal("person:bob"), proposal["proposal_id"])
    assert exc.value.code == "not_executable"
    state = await env.svc.get(env.principal("person:bob"), proposal["proposal_id"])
    assert state["state"] == "expired"


async def test_pending_expires_after_a_day(env: Env) -> None:
    proposal = await _propose_note(env)
    env.clock.advance(hours=25)
    with pytest.raises(ApprovalError):
        await env.svc.approve(proposal["proposal_id"], CAROL)
    state = await env.svc.get(env.principal("person:bob"), proposal["proposal_id"])
    assert state["state"] == "expired"


async def test_tampered_sql_is_refused_at_execution(env: Env, pg_admin_dsn: str) -> None:
    from urllib.parse import urlsplit, urlunsplit

    proposal = await _propose_note(env)
    await env.svc.approve(proposal["proposal_id"], CAROL)
    parts = urlsplit(pg_admin_dsn)
    state_admin = urlunsplit((parts.scheme, parts.netloc, "/pgw_state", parts.query, ""))
    conn = await asyncpg.connect(state_admin, timeout=5)
    try:
        await conn.execute(
            "UPDATE pgwarden.proposals SET sql_text = 'DELETE FROM ticket_notes' WHERE id = $1",
            proposal["proposal_id"],
        )
    finally:
        await conn.close()
    before = await _count(env, "SELECT count(*) FROM ticket_notes")
    with pytest.raises(ApprovalError) as exc:
        await env.svc.execute(env.principal("person:bob"), proposal["proposal_id"])
    assert exc.value.code == "binding_mismatch"
    assert await _count(env, "SELECT count(*) FROM ticket_notes") == before


async def test_concurrent_execution_runs_exactly_once(env: Env) -> None:
    proposal = await _propose_note(env)
    await env.svc.approve(proposal["proposal_id"], CAROL)
    before = await _count(env, "SELECT count(*) FROM ticket_notes")
    bob = env.principal("person:bob")
    results = await asyncio.gather(
        env.svc.execute(bob, proposal["proposal_id"]),
        env.svc.execute(bob, proposal["proposal_id"]),
        return_exceptions=True,
    )
    executed = [r for r in results if isinstance(r, dict) and r.get("state") == "executed"]
    refused = [r for r in results if isinstance(r, ApprovalError)]
    assert len(executed) == 1 and len(refused) == 1
    assert await _count(env, "SELECT count(*) FROM ticket_notes") == before + 1


# -- execution outcomes decided by the database ---------------------------------------


async def test_max_rows_exceeded_rolls_back(env: Env) -> None:
    before = await _count(
        env, "SELECT count(*) FROM support_tickets WHERE region = 'EU' AND status = 'on_hold'"
    )
    proposal = await env.svc.propose(
        env.principal("person:bob"),
        sql="UPDATE support_tickets SET status = $1 WHERE region = $2",
        params=["on_hold", "EU"],
        reason="bulk hold",
        max_rows=1,
        client_id=None,
    )
    await env.svc.approve(proposal["proposal_id"], CAROL)
    result = await env.svc.execute(env.principal("person:bob"), proposal["proposal_id"])
    assert result["state"] == "failed" and result["rows_affected"] > 1
    after = await _count(
        env, "SELECT count(*) FROM support_tickets WHERE region = 'EU' AND status = 'on_hold'"
    )
    assert after == before


async def test_rls_with_check_blocks_a_foreign_region_write(env: Env) -> None:
    before = await _count(env, "SELECT count(*) FROM ticket_notes WHERE region = 'US'")
    proposal = await _propose_note(env, region="US")
    await env.svc.approve(proposal["proposal_id"], CAROL)
    result = await env.svc.execute(env.principal("person:bob"), proposal["proposal_id"])
    assert result["state"] == "failed"
    # The demo derives a note's region from its ticket in a BEFORE INSERT trigger;
    # bob cannot see the US ticket under RLS, so the trigger refuses first (P0001).
    # RLS WITH CHECK (42501) is the backstop if the region were ever supplied.
    assert result["error"]["sqlstate"] in {"P0001", "42501"}
    assert await _count(env, "SELECT count(*) FROM ticket_notes WHERE region = 'US'") == before


async def test_update_of_an_invisible_row_affects_nothing(env: Env) -> None:
    us_ticket = await _ticket_id(env, "US")
    proposal = await env.svc.propose(
        env.principal("person:bob"),
        sql="UPDATE support_tickets SET status = $1 WHERE id = $2",
        params=["closed", us_ticket],
        reason="close it",
        max_rows=1,
        client_id=None,
    )
    await env.svc.approve(proposal["proposal_id"], CAROL)
    result = await env.svc.execute(env.principal("person:bob"), proposal["proposal_id"])
    assert result["state"] == "executed" and result["rows_affected"] == 0


async def test_refund_over_the_check_limit_fails(env: Env) -> None:
    ticket = await _ticket_id(env, "EU")
    proposal = await env.svc.propose(
        env.principal("person:bob"),
        sql="INSERT INTO refunds (ticket_id, region, amount, reason) VALUES ($1, $2, $3, $4)",
        params=[ticket, "EU", 600, "goodwill"],
        reason="goodwill refund",
        max_rows=1,
        client_id=None,
    )
    await env.svc.approve(proposal["proposal_id"], CAROL)
    result = await env.svc.execute(env.principal("person:bob"), proposal["proposal_id"])
    assert result["state"] == "failed" and result["error"]["sqlstate"] == "23514"


async def test_proposal_rate_limit(
    pg_demo_masking: None,
    pg_target_dsn: str,
    pg_state_dsn: str,
    pg_role_secret: str,
    pg_shop_dsn: str,
    pg_demo_config: object,
) -> None:
    assert isinstance(pg_demo_config, Config)
    config = pg_demo_config.model_copy(
        update={"limits": pg_demo_config.limits.model_copy(update={"proposals_per_hour": 1})}
    )
    async for e in _make_env(config, pg_target_dsn, pg_state_dsn, pg_role_secret, pg_shop_dsn):
        e.clock.now = dt.datetime(2031, 1, 1, tzinfo=dt.UTC)  # a window no other test uses
        await _propose_note(e, subject="person:dana", region="US")
        with pytest.raises(ApprovalError) as exc:
            await _propose_note(e, subject="person:dana", region="US")
        assert exc.value.code == "rate_limited" and exc.value.retry_after_s
