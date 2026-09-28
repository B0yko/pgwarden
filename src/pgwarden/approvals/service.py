"""The approval queue (item 7): propose, review, approve or reject, execute.

* ``propose`` validates the write by Postgres (``approvals.validate``), stores
  the exact SQL and parameters with an HMAC binding over (SQL, parameters,
  writer role), audits the proposal and notifies the approvers with a summary
  and a signed link.
* ``approve`` / ``reject`` require an identity that matches ``approvers`` in
  config and refuse self-approval. Approval creates a single-use grant valid
  for ``write.grant_ttl_s`` (15 minutes by default).
* ``execute`` checks that the caller is the proposer and that the binding still
  matches, claims the grant atomically and inserts an audit ``started`` row in
  the same state-database transaction (fail-closed), then runs the *stored*
  statement on the person's own connection as their writer role. More rows
  than ``max_rows`` rolls back and fails the proposal. A crash after the claim
  leaves the proposal ``executing``, and it can never run again.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import secrets
from typing import Any

import asyncpg

from pgwarden.approvals.links import approval_link, binding_hmac
from pgwarden.approvals.notifiers import ApprovalNotice, Notifier, notify_all
from pgwarden.approvals.validate import validate_write
from pgwarden.config import Config
from pgwarden.db.params import coerce_params
from pgwarden.identity import Principal, UpstreamIdentity, ref_matches
from pgwarden.mcp_server import GatewayDeps
from pgwarden.state import audit, ratelimit
from pgwarden.state.audit import AuditError
from pgwarden.state.conn import AnyConn

MAX_ROWS_LIMIT = 100_000
MAX_REASON_CHARS = 2000

_EXEC_SET_CONFIG_SQL = (
    "SELECT set_config('role', $1, true), "
    "set_config('statement_timeout', $2, true), "
    "set_config('lock_timeout', $3, true), "
    "set_config('application_name', $4, true)"
)


class ApprovalError(Exception):
    """A refused write-path request, with a stable machine-readable code."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        sqlstate: str | None = None,
        retry_after_s: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.sqlstate = sqlstate
        self.retry_after_s = retry_after_s

    def as_tool_error(self) -> dict[str, Any]:
        err: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "sqlstate": self.sqlstate,
        }
        if self.retry_after_s is not None:
            err["retryable"] = True
            err["retry_after_s"] = self.retry_after_s
        return {"error": err}


def canonical_params(params: list[Any]) -> str:
    return json.dumps(params, sort_keys=True, separators=(",", ":"), default=str)


def _iso(value: dt.datetime | None) -> str | None:
    return value.astimezone(dt.UTC).isoformat() if value is not None else None


@dataclasses.dataclass
class ApprovalService:
    gateway: GatewayDeps
    session_secret: str
    notifiers: list[Notifier] = dataclasses.field(default_factory=list)

    @property
    def config(self) -> Config:
        return self.gateway.config

    def now(self) -> dt.datetime:
        return self.gateway.now()

    # -- helpers ----------------------------------------------------------------

    def _binding(self, sql: str, params_json: str, writer_role: str) -> str:
        return binding_hmac(self.session_secret, sql, params_json, writer_role)

    async def _audit(self, conn: AnyConn, **fields: Any) -> None:
        try:
            await audit.record(conn, **fields)
        except AuditError as exc:
            raise ApprovalError(
                "audit_unavailable", "audit log unavailable; refusing (fail-closed)"
            ) from exc

    async def _expire_due(self, conn: AnyConn, proposal_id: str | None = None) -> int:
        """Move due proposals to 'expired' (all of them, or one), auditing each."""
        now = self.now()
        where_id = "AND id = $2" if proposal_id is not None else ""
        args: list[Any] = [now] + ([proposal_id] if proposal_id is not None else [])
        rows = await conn.fetch(
            "UPDATE pgwarden.proposals "
            "SET state = 'expired', decided_at = COALESCE(decided_at, $1) "
            "WHERE ((state = 'pending' AND expires_at <= $1) "
            f"OR (state = 'approved' AND grant_expires_at <= $1)) {where_id} "
            "RETURNING id, proposer_subject, pg_role",
            *args,
        )
        for row in rows:
            await self._audit(
                conn,
                event="proposal",
                outcome="ok",
                tool="proposal.expire",
                request_id=row["id"],
                identity_sub=row["proposer_subject"],
                pg_role=row["pg_role"],
            )
        return len(rows)

    async def _load(self, conn: AnyConn, proposal_id: str) -> asyncpg.Record | None:
        return await conn.fetchrow("SELECT * FROM pgwarden.proposals WHERE id = $1", proposal_id)

    def _public_view(self, row: asyncpg.Record) -> dict[str, Any]:
        return {
            "proposal_id": row["id"],
            "state": row["state"],
            "sql": row["sql_text"],
            "reason": row["reason"],
            "max_rows": row["max_rows"],
            "plan": {
                "operation": row["plan_operation"],
                "relation": row["plan_relation"],
                "estimated_rows": row["plan_rows_estimate"],
            },
            "created_at": _iso(row["created_at"]),
            "expires_at": _iso(row["expires_at"]),
            "decided_at": _iso(row["decided_at"]),
            "grant_expires_at": _iso(row["grant_expires_at"]),
            "executed_at": _iso(row["executed_at"]),
            "rows_affected": row["rows_affected"],
            "error": row["error"],
        }

    def review_view(self, row: asyncpg.Record) -> dict[str, Any]:
        """Everything an approver needs: the full SQL, parameters and plan estimate."""
        view = self._public_view(row)
        params = row["params"]
        view["params"] = json.loads(params) if isinstance(params, str) else params
        view["proposer"] = row["proposer_email"] or row["proposer_subject"]
        view["pg_role"] = row["pg_role"]
        view["writer_role"] = row["writer_role"]
        view["approver"] = row["approver_email"] or row["approver_subject"]
        return view

    # -- propose ----------------------------------------------------------------

    async def propose(
        self,
        principal: Principal,
        *,
        sql: str,
        params: list[Any],
        reason: str,
        max_rows: int,
        client_id: str | None,
    ) -> dict[str, Any]:
        if principal.writer is None:
            raise ApprovalError("no_writer_role", "you have no writer role; writes are not allowed")
        if not isinstance(max_rows, int) or not 1 <= max_rows <= MAX_ROWS_LIMIT:
            raise ApprovalError("invalid_request", f"max_rows must be 1..{MAX_ROWS_LIMIT}")
        if not isinstance(reason, str) or not reason.strip():
            raise ApprovalError("invalid_request", "a reason is required")
        reason = reason.strip()[:MAX_REASON_CHARS]
        params_json = canonical_params(params)
        now = self.now()
        pool = self.gateway.require_state_pool()

        async with pool.acquire() as conn:
            limit = await ratelimit.check_and_increment(
                conn,
                "proposal",
                principal.subject,
                limit=principal.proposals_per_hour,
                window_seconds=3600,
                now=now,
            )
            if not limit.allowed:
                await self._audit(
                    conn,
                    event="proposal",
                    outcome="rate_limited",
                    tool="proposal.propose",
                    identity_sub=principal.subject,
                    identity_email=principal.email,
                    pg_role=principal.role_name,
                    client_id=client_id,
                    sql_text=sql,
                    params_sha256=audit.hash_params(params),
                )
                raise ApprovalError(
                    "rate_limited",
                    f"proposal rate limit exceeded ({limit.limit} per hour)",
                    retry_after_s=limit.retry_after_s,
                )

        validation = await validate_write(
            self.gateway.pool_manager,
            principal.role_name,
            principal.writer,
            sql,
            params,
            statement_timeout_ms=self.config.write.statement_timeout_ms,
        )
        async with pool.acquire() as conn:
            if not validation.ok or validation.plan is None:
                await self._audit(
                    conn,
                    event="proposal",
                    outcome="blocked",
                    tool="proposal.propose",
                    identity_sub=principal.subject,
                    identity_email=principal.email,
                    pg_role=principal.role_name,
                    client_id=client_id,
                    sql_text=sql,
                    params_sha256=audit.hash_params(params),
                    sqlstate=validation.sqlstate,
                )
                raise ApprovalError(
                    "rejected_by_validation",
                    validation.reason or "the statement is not an acceptable write",
                    sqlstate=validation.sqlstate,
                )

            plan = validation.plan
            proposal_id = secrets.token_urlsafe(16)
            expires_at = now + dt.timedelta(seconds=self.config.write.pending_ttl_s)
            async with conn.transaction():
                await conn.execute(
                    "INSERT INTO pgwarden.proposals (id, state, sql_text, params, binding_sha256, "
                    "proposer_subject, proposer_email, pg_role, writer_role, client_id, reason, "
                    "max_rows, plan_operation, plan_relation, plan_rows_estimate, created_at, "
                    "expires_at) VALUES ($1, 'pending', $2, $3::jsonb, $4, $5, $6, $7, $8, $9, "
                    "$10, $11, $12, $13, $14, $15, $16)",
                    proposal_id,
                    sql,
                    params_json,
                    self._binding(sql, params_json, principal.writer),
                    principal.subject,
                    principal.email,
                    principal.role_name,
                    principal.writer,
                    client_id,
                    reason,
                    max_rows,
                    plan.operation,
                    plan.relation,
                    plan.estimated_rows,
                    now,
                    expires_at,
                )
                await self._audit(
                    conn,
                    event="proposal",
                    outcome="ok",
                    tool="proposal.propose",
                    request_id=proposal_id,
                    identity_sub=principal.subject,
                    identity_email=principal.email,
                    pg_role=principal.role_name,
                    client_id=client_id,
                    sql_text=sql,
                    params_sha256=audit.hash_params(params),
                )

        notice = ApprovalNotice(
            proposal_id=proposal_id,
            proposer=principal.email or principal.subject,
            operation=plan.operation,
            relation=plan.relation,
            estimated_rows=plan.estimated_rows,
            expires_at=expires_at,
            link=approval_link(self.config.public_url, self.session_secret, proposal_id, now=now),
        )
        failed_channels = await notify_all(self.notifiers, notice)
        return {
            "proposal_id": proposal_id,
            "state": "pending",
            "plan": {
                "operation": plan.operation,
                "relation": plan.relation,
                "estimated_rows": plan.estimated_rows,
            },
            "expires_at": _iso(expires_at),
            "notified": [n.name for n in self.notifiers if n.name not in failed_channels],
            "next_step": (
                "A named human approver must approve this proposal. After approval, call "
                "execute_approved_write with this proposal_id within the grant window."
            ),
        }

    # -- read -----------------------------------------------------------------------

    async def get(self, principal: Principal, proposal_id: str) -> dict[str, Any]:
        async with self.gateway.require_state_pool().acquire() as conn:
            await self._expire_due(conn, proposal_id)
            row = await self._load(conn, proposal_id)
        if row is None or row["proposer_subject"] != principal.subject:
            raise ApprovalError("not_found", "no such proposal")
        return self._public_view(row)

    async def get_for_review(self, proposal_id: str) -> dict[str, Any] | None:
        async with self.gateway.require_state_pool().acquire() as conn:
            await self._expire_due(conn, proposal_id)
            row = await self._load(conn, proposal_id)
        return self.review_view(row) if row is not None else None

    async def list_for_review(self, *, limit: int = 100) -> list[dict[str, Any]]:
        async with self.gateway.require_state_pool().acquire() as conn:
            await self._expire_due(conn)
            rows = await conn.fetch(
                "SELECT * FROM pgwarden.proposals ORDER BY created_at DESC LIMIT $1", limit
            )
        return [self.review_view(r) for r in rows]

    async def expire_stale(self) -> int:
        async with self.gateway.require_state_pool().acquire() as conn:
            return await self._expire_due(conn)

    # -- approve / reject --------------------------------------------------------------

    def is_approver(self, identity: UpstreamIdentity) -> bool:
        return any(ref_matches(ref, identity) for ref in self.config.approvers)

    def _is_self(self, row: asyncpg.Record, identity: UpstreamIdentity) -> bool:
        subject = str(row["proposer_subject"])
        kind, _, suffix = subject.partition(":")
        if kind == "person":
            for person in self.config.people:
                if person.role == suffix and ref_matches(person.identity, identity):
                    return True
        email = row["proposer_email"]
        return bool(email and identity.email and email.lower() == identity.email.lower())

    async def decide(
        self, proposal_id: str, approver: UpstreamIdentity, *, approve: bool
    ) -> dict[str, Any]:
        action = "proposal.approve" if approve else "proposal.reject"
        now = self.now()
        async with self.gateway.require_state_pool().acquire() as conn:
            if not self.is_approver(approver):
                await self._audit(
                    conn,
                    event="approval",
                    outcome="denied",
                    tool=action,
                    request_id=proposal_id,
                    identity_sub=approver.subject,
                    identity_email=approver.email,
                )
                raise ApprovalError("not_an_approver", "you are not a configured approver")
            await self._expire_due(conn, proposal_id)
            row = await self._load(conn, proposal_id)
            if row is None:
                raise ApprovalError("not_found", "no such proposal")
            if self._is_self(row, approver):
                await self._audit(
                    conn,
                    event="approval",
                    outcome="denied",
                    tool=action,
                    request_id=proposal_id,
                    identity_sub=approver.subject,
                    identity_email=approver.email,
                )
                raise ApprovalError("self_approval", "you cannot approve your own proposal")

            async with conn.transaction():
                if approve:
                    updated = await conn.fetchrow(
                        "UPDATE pgwarden.proposals SET state = 'approved', approver_provider = $2, "
                        "approver_subject = $3, approver_email = $4, decided_at = $5, "
                        "grant_expires_at = $6, approved_binding = binding_sha256 "
                        "WHERE id = $1 AND state = 'pending' AND expires_at > $5 RETURNING *",
                        proposal_id,
                        approver.provider,
                        approver.subject,
                        approver.email,
                        now,
                        now + dt.timedelta(seconds=self.config.write.grant_ttl_s),
                    )
                else:
                    updated = await conn.fetchrow(
                        "UPDATE pgwarden.proposals SET state = 'rejected', approver_provider = $2, "
                        "approver_subject = $3, approver_email = $4, decided_at = $5 "
                        "WHERE id = $1 AND state = 'pending' AND expires_at > $5 RETURNING *",
                        proposal_id,
                        approver.provider,
                        approver.subject,
                        approver.email,
                        now,
                    )
                if updated is None:
                    raise ApprovalError(
                        "not_pending", f"the proposal is {row['state']}, not pending"
                    )
                await self._audit(
                    conn,
                    event="approval",
                    outcome="ok",
                    tool=action,
                    request_id=proposal_id,
                    identity_sub=approver.subject,
                    identity_email=approver.email,
                    pg_role=row["pg_role"],
                )
        return self.review_view(updated)

    async def approve(self, proposal_id: str, approver: UpstreamIdentity) -> dict[str, Any]:
        return await self.decide(proposal_id, approver, approve=True)

    async def reject(self, proposal_id: str, approver: UpstreamIdentity) -> dict[str, Any]:
        return await self.decide(proposal_id, approver, approve=False)

    # -- execute ---------------------------------------------------------------------------

    async def execute(self, principal: Principal, proposal_id: str) -> dict[str, Any]:
        pool = self.gateway.require_state_pool()
        now = self.now()
        async with pool.acquire() as conn:
            await self._expire_due(conn, proposal_id)
            row = await self._load(conn, proposal_id)
            if row is None or row["proposer_subject"] != principal.subject:
                raise ApprovalError("not_found", "no such proposal")

            params_raw = row["params"]
            params_json = params_raw if isinstance(params_raw, str) else json.dumps(params_raw)
            params = json.loads(params_json)
            expected = self._binding(row["sql_text"], canonical_params(params), row["writer_role"])
            if expected != row["binding_sha256"] or (
                row["approved_binding"] is not None and row["approved_binding"] != expected
            ):
                await self._audit(
                    conn,
                    event="proposal",
                    outcome="denied",
                    tool="proposal.execute",
                    request_id=proposal_id,
                    identity_sub=principal.subject,
                    pg_role=principal.role_name,
                )
                raise ApprovalError(
                    "binding_mismatch", "the stored statement no longer matches what was approved"
                )

            async with conn.transaction():
                claimed = await conn.fetchrow(
                    "UPDATE pgwarden.proposals SET state = 'executing' "
                    "WHERE id = $1 AND state = 'approved' AND grant_expires_at > $2 "
                    "RETURNING sql_text, writer_role, max_rows",
                    proposal_id,
                    now,
                )
                if claimed is None:
                    raise ApprovalError(
                        "not_executable",
                        f"the proposal is {row['state']}; only an approved, unexpired grant "
                        "can execute, once",
                    )
                # Fail-closed: the started row commits with the claim or not at all.
                await self._audit(
                    conn,
                    event="proposal",
                    outcome="started",
                    tool="proposal.execute",
                    request_id=proposal_id,
                    identity_sub=principal.subject,
                    identity_email=principal.email,
                    pg_role=principal.role_name,
                    sql_text=claimed["sql_text"],
                    params_sha256=audit.hash_params(params),
                )

        rows_affected, error_sqlstate, error = await self._run_stored(
            principal,
            sql=str(claimed["sql_text"]),
            params=params,
            writer_role=str(claimed["writer_role"]),
            max_rows=int(claimed["max_rows"]),
        )
        final_state = "executed" if error is None else "failed"
        async with pool.acquire() as conn, conn.transaction():
            await conn.execute(
                "UPDATE pgwarden.proposals SET state = $2, executed_at = $3, rows_affected = $4, "
                "error_sqlstate = $5, error = $6 WHERE id = $1 AND state = 'executing'",
                proposal_id,
                final_state,
                self.now(),
                rows_affected,
                error_sqlstate,
                error,
            )
            await self._audit(
                conn,
                event="proposal",
                outcome="ok" if error is None else "error",
                tool="proposal.execute",
                request_id=proposal_id,
                identity_sub=principal.subject,
                identity_email=principal.email,
                pg_role=principal.role_name,
                rows_affected=rows_affected,
                sqlstate=error_sqlstate,
            )
        result: dict[str, Any] = {
            "proposal_id": proposal_id,
            "state": final_state,
            "rows_affected": rows_affected,
        }
        if error is not None:
            result["error"] = {
                "code": "execution_failed",
                "message": error,
                "sqlstate": error_sqlstate,
            }
        return result

    async def _run_stored(
        self,
        principal: Principal,
        *,
        sql: str,
        params: list[Any],
        writer_role: str,
        max_rows: int,
    ) -> tuple[int | None, str | None, str | None]:
        """Run the stored statement as the writer role; returns (rows, sqlstate, error)."""
        try:
            async with self.gateway.pool_manager.acquire(principal.role_name) as conn:
                tx = conn.transaction()
                await tx.start()
                try:
                    # Overrides the role's default_transaction_read_only for this
                    # transaction only (it must be the first statement).
                    await conn.execute("SET TRANSACTION READ WRITE")
                    await conn.execute(
                        _EXEC_SET_CONFIG_SQL,
                        writer_role,
                        str(self.config.write.statement_timeout_ms),
                        str(self.config.read.lock_timeout_ms),
                        f"pgwarden:{principal.role_name}:execute",
                    )
                    # Extended protocol only: the stored statement is prepared,
                    # never sent through the simple query protocol.
                    stmt = await conn.prepare(sql)
                    await stmt.fetch(*coerce_params(params, stmt.get_parameters()))
                    rows = _rows_from_tag(stmt.get_statusmsg())
                    if rows > max_rows:
                        await tx.rollback()
                        return (
                            rows,
                            None,
                            f"the statement affected {rows} rows, more than max_rows={max_rows}; "
                            "rolled back",
                        )
                except BaseException:
                    await tx.rollback()
                    raise
                await tx.commit()
                return rows, None, None
        except asyncpg.PostgresError as exc:
            return None, getattr(exc, "sqlstate", None), str(exc)


def _rows_from_tag(tag: str | None) -> int:
    """Rows from a command tag: 'UPDATE 3', 'DELETE 0', 'INSERT 0 1'."""
    parts = (tag or "").split()
    return int(parts[-1]) if parts and parts[-1].isdigit() else 0


__all__ = [
    "MAX_ROWS_LIMIT",
    "ApprovalError",
    "ApprovalService",
    "canonical_params",
]
