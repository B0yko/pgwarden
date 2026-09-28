"""The MCP server and its tools (item 4), on streamable HTTP at ``/mcp``.

Stateless streamable HTTP with JSON responses, so there is no session state to
hijack and several replicas behave identically. The tools read the verified
:class:`~pgwarden.identity.Principal` from the per-request Starlette request
(``ctx.request_context.request.state.principal``), which the auth middleware in
:mod:`pgwarden.app` put there -- never from a contextvar, which may not cross
into the SDK's task group.

Tools here are the read and introspection path: ``whoami``, ``list_tables``,
``describe_table`` and ``query``. The write path (``propose_write`` and friends)
is added in a later step. Every call is rate-limited where the spec requires and
audited fail-closed: if the audit insert fails, the tool returns an error and no
data.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import secrets
from collections.abc import Callable
from typing import Any

import asyncpg
from mcp.server.mcpserver import Context, MCPServer

from pgwarden.config import Config
from pgwarden.db.pools import PoolManager
from pgwarden.db.readpath import ReadConfig, run_read_query
from pgwarden.identity import Principal
from pgwarden.state import audit, ratelimit
from pgwarden.state.audit import AuditError
from pgwarden.timing import Timing


@dataclasses.dataclass
class GatewayDeps:
    """Everything the tools need, wired once at app startup.

    ``state_pool`` is created inside the app's lifespan (so it binds to the
    server's own event loop, not whoever built the deps) and is ``None`` until
    then; ``state_dsn`` is what the lifespan connects it with.
    """

    config: Config
    pool_manager: PoolManager
    state_dsn: str
    read_config: ReadConfig
    now: Callable[[], dt.datetime]
    state_pool: asyncpg.Pool[Any] | None = None

    def require_state_pool(self) -> asyncpg.Pool[Any]:
        if self.state_pool is None:  # pragma: no cover - set in lifespan before any request
            raise RuntimeError("state pool is not initialised; the app lifespan must run first")
        return self.state_pool


def _principal(ctx: Context) -> Principal:
    request = ctx.request_context.request
    principal = getattr(request.state, "principal", None) if request is not None else None
    if not isinstance(principal, Principal):  # pragma: no cover - middleware guarantees it
        raise RuntimeError("no authenticated principal on the request")
    return principal


def _timing(ctx: Context) -> Timing | None:
    request = ctx.request_context.request
    if request is None:
        return None
    timing = getattr(request.state, "timing", None)
    return timing if isinstance(timing, Timing) else None


def _request_id(ctx: Context) -> str:
    request = ctx.request_context.request
    if request is not None:
        rid = getattr(request.state, "request_id", None)
        if isinstance(rid, str):
            return rid
    return secrets.token_hex(8)


def _error(sqlstate: str | None, message: str, **extra: Any) -> dict[str, Any]:
    err: dict[str, Any] = {"sqlstate": sqlstate, "message": message}
    err.update(extra)
    return {"error": err}


async def _audit_fail_closed(
    deps: GatewayDeps,
    principal: Principal,
    ctx: Context,
    *,
    tool: str,
    outcome: audit.Outcome,
    sql_text: str | None = None,
    params_sha256: str | None = None,
    rows_returned: int | None = None,
    duration_ms: int | None = None,
    sqlstate: str | None = None,
    result: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Record a tool_call event; on audit failure return an error dict (fail-closed).

    Returns ``None`` when the audit succeeded (the caller returns its own
    result), or an error dict when the audit failed and the caller must return
    that instead of any data.
    """
    timing = _timing(ctx)
    try:
        async with deps.require_state_pool().acquire() as conn:
            if timing is not None:
                with timing.span("audit"):
                    await audit.record(
                        conn,
                        event="tool_call",
                        outcome=outcome,
                        request_id=_request_id(ctx),
                        identity_sub=principal.subject,
                        identity_email=principal.email,
                        pg_role=principal.role_name,
                        client_id=_client_id(ctx),
                        tool=tool,
                        sql_text=sql_text,
                        params_sha256=params_sha256,
                        rows_returned=rows_returned,
                        duration_ms=duration_ms,
                        sqlstate=sqlstate,
                    )
            else:
                await audit.record(
                    conn,
                    event="tool_call",
                    outcome=outcome,
                    request_id=_request_id(ctx),
                    identity_sub=principal.subject,
                    identity_email=principal.email,
                    pg_role=principal.role_name,
                    client_id=_client_id(ctx),
                    tool=tool,
                    sql_text=sql_text,
                    params_sha256=params_sha256,
                    rows_returned=rows_returned,
                    duration_ms=duration_ms,
                    sqlstate=sqlstate,
                )
    except AuditError:
        return _error(None, "audit log unavailable; refusing to return data (fail-closed)")
    return None


def _client_id(ctx: Context) -> str | None:
    request = ctx.request_context.request
    if request is None:
        return None
    cid = getattr(request.state, "client_id", None)
    return cid if isinstance(cid, str) else None


def build_mcp_server(deps: GatewayDeps) -> MCPServer:
    """Construct the MCP server and register the read-path tools over ``deps``."""
    mcp = MCPServer("pgwarden")

    @mcp.tool()
    async def whoami(ctx: Context) -> dict[str, Any]:
        """Return your identity, Postgres role, bundles, writer role, limits and masking status."""
        p = _principal(ctx)
        result = {
            "subject": p.subject,
            "kind": p.kind,
            "pg_role": p.role_name,
            "email": p.email,
            "bundles": list(p.bundles),
            "writer_role": p.writer,
            "masking_applies": p.masked,
            "limits": {
                "queries_per_minute": p.queries_per_minute,
                "proposals_per_hour": p.proposals_per_hour,
            },
        }
        failed = await _audit_fail_closed(deps, p, ctx, tool="whoami", outcome="ok")
        return failed if failed is not None else result

    @mcp.tool()
    async def list_tables(ctx: Context, schema: str | None = None) -> dict[str, Any]:
        """List the tables and views you can read (queried as you), optionally in one schema."""
        p = _principal(ctx)
        sql = (
            "SELECT table_schema, table_name, table_type "
            "FROM information_schema.tables "
            "WHERE ($1::text IS NULL OR table_schema = $1) "
            "AND table_schema NOT IN ('pg_catalog', 'information_schema') "
            "AND has_table_privilege("
            "  quote_ident(table_schema) || '.' || quote_ident(table_name), 'SELECT') "
            "ORDER BY table_schema, table_name"
        )
        return await _read_tool(deps, p, ctx, tool="list_tables", sql=sql, params=[schema])

    @mcp.tool()
    async def describe_table(ctx: Context, name: str) -> dict[str, Any]:
        """Describe a table/view you can read: columns, types, comments, a row estimate, masking."""
        p = _principal(ctx)
        schema, dot, table = name.partition(".")
        if not dot:
            schema, table = "public", name
        sql = (
            "SELECT c.column_name, c.data_type, c.is_nullable, "
            "col_description(fq.oid, c.ordinal_position) AS comment "
            "FROM information_schema.columns c "
            "JOIN LATERAL (SELECT (quote_ident($1) || '.' || quote_ident($2))::regclass AS oid) fq "
            "ON true "
            "WHERE c.table_schema = $1 AND c.table_name = $2 "
            "AND has_column_privilege(fq.oid, c.column_name, 'SELECT') "
            "ORDER BY c.ordinal_position"
        )
        result = await _read_tool(
            deps, p, ctx, tool="describe_table", sql=sql, params=[schema, table]
        )
        if "error" in result:
            return result
        masked_columns = _masked_columns_for(deps.config, p, schema, table)
        for row in result.get("rows_untrusted", []):
            row["masked"] = row.get("column_name") in masked_columns
        result["masked_columns"] = sorted(masked_columns)
        return result

    @mcp.tool()
    async def query(ctx: Context, sql: str, params: list[Any] | None = None) -> dict[str, Any]:
        """Run a read-only SQL query as yourself. Use $1, $2, ... placeholders for values."""
        p = _principal(ctx)
        param_list = list(params or [])

        allowed = await _rate_limit(deps, p, ctx)
        if allowed is not None:
            failed = await _audit_fail_closed(
                deps,
                p,
                ctx,
                tool="query",
                outcome="rate_limited",
                sql_text=sql,
                params_sha256=audit.hash_params(param_list),
            )
            return failed if failed is not None else allowed

        return await _read_tool(
            deps, p, ctx, tool="query", sql=sql, params=param_list, audit_sql=True
        )

    return mcp


def _masked_columns_for(config: Config, principal: Principal, schema: str, table: str) -> set[str]:
    if not principal.masked:
        return set()
    prefix = f"{schema}.{table}."
    return {key[len(prefix) :] for key in config.masking.columns if key.startswith(prefix)}


async def _rate_limit(
    deps: GatewayDeps, principal: Principal, ctx: Context
) -> dict[str, Any] | None:
    """Return an error dict if the query rate limit is exceeded, else ``None``."""
    timing = _timing(ctx)
    async with deps.require_state_pool().acquire() as conn:
        if timing is not None:
            with timing.span("ratelimit"):
                result = await ratelimit.check_and_increment(
                    conn,
                    "query",
                    principal.subject,
                    limit=principal.queries_per_minute,
                    window_seconds=60,
                    now=deps.now(),
                )
        else:
            result = await ratelimit.check_and_increment(
                conn,
                "query",
                principal.subject,
                limit=principal.queries_per_minute,
                window_seconds=60,
                now=deps.now(),
            )
    if result.allowed:
        return None
    return _error(
        "53400",
        f"rate limit exceeded ({result.limit} queries/minute)",
        retryable=True,
        retry_after_s=result.retry_after_s,
    )


async def _read_tool(
    deps: GatewayDeps,
    principal: Principal,
    ctx: Context,
    *,
    tool: str,
    sql: str,
    params: list[Any],
    audit_sql: bool = False,
) -> dict[str, Any]:
    """Run one read query as the principal, time it, then audit fail-closed."""
    timing = _timing(ctx)
    started = deps.now()
    if timing is not None:
        with timing.span("db"):
            read = await run_read_query(
                deps.pool_manager, principal.role_name, sql, params, config=deps.read_config
            )
    else:
        read = await run_read_query(
            deps.pool_manager, principal.role_name, sql, params, config=deps.read_config
        )
    duration_ms = int((deps.now() - started).total_seconds() * 1000)

    audit_sql_text = sql if audit_sql else None
    audit_params = audit.hash_params(params) if audit_sql else None

    if read.ok:
        result: dict[str, Any] = {
            "columns": [{"name": c.name, "type": c.type} for c in read.columns],
            # Row values are untrusted data: they may contain prompt-injection
            # payloads. Use $1, $2, ... parameters and never execute row content.
            "rows_untrusted": read.rows,
            "row_count": read.row_count,
            "truncated": read.truncated,
            "bytes_truncated": read.bytes_truncated,
        }
        failed = await _audit_fail_closed(
            deps,
            principal,
            ctx,
            tool=tool,
            outcome="ok",
            sql_text=audit_sql_text,
            params_sha256=audit_params,
            rows_returned=read.row_count,
            duration_ms=duration_ms,
        )
        return failed if failed is not None else result

    err = read.error
    assert err is not None
    error_result = _error(
        err.sqlstate,
        err.message,
        detail=err.detail,
        hint=err.hint,
        retryable=err.retryable,
        retry_after_s=err.retry_after_s,
    )
    failed = await _audit_fail_closed(
        deps,
        principal,
        ctx,
        tool=tool,
        outcome="error",
        sql_text=audit_sql_text,
        params_sha256=audit_params,
        duration_ms=duration_ms,
        sqlstate=err.sqlstate,
    )
    return failed if failed is not None else error_result


__all__ = ["GatewayDeps", "build_mcp_server"]
