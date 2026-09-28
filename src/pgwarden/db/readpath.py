"""The read path: item 5 of the spec, run for every MCP `query` call.

Exact sequence, with no SQL parsing or rewriting anywhere in this module:

1. Acquire a connection from the principal's pool (:mod:`pgwarden.db.pools`).
2. ``BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY`` -- via
   ``Connection.transaction(isolation="repeatable_read", readonly=True)``,
   not a raw ``conn.execute("BEGIN ...")``. This is required, not stylistic:
   ``PreparedStatement.cursor()`` refuses to open a portal unless asyncpg's
   own ``Connection._top_xact`` is set (``NoActiveSQLTransactionError:
   cursor cannot be created outside of a transaction`` -- verified by
   experiment), and only ``Connection.transaction()`` sets it; a bare
   ``conn.execute("BEGIN ...")`` leaves Postgres itself in a transaction
   (confirmed via ``is_in_transaction()``) but does not satisfy asyncpg's
   own bookkeeping. ``Transaction.start()`` with these arguments sends
   exactly ``BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;`` (verified
   against the asyncpg source), and this module always calls
   ``Transaction.rollback()`` explicitly in a ``finally`` block, never
   ``commit()`` -- step 8 below.
3. One ``SELECT set_config(...)`` statement with bound values for
   ``statement_timeout``, ``lock_timeout``, ``idle_in_transaction_session_timeout``
   and ``application_name``. Values are never interpolated into the SQL
   text.
4. Prepare the user's statement via ``conn.prepare()`` (the extended
   protocol's Parse). A second statement in the same text is rejected here
   by Postgres itself with SQLSTATE 42601 (verified: ``conn.prepare("select
   1; select 2;")`` raises ``PostgresSyntaxError`` -- "cannot insert
   multiple commands into a prepared statement"); this module adds no
   multi-statement detection of its own.
5. Bind parameters coerced from JSON to the prepared statement's declared
   types (:mod:`pgwarden.db.params`).
6. Fetch at most ``row_cap + 1`` rows through a portal
   (``PreparedStatement.cursor()``), then stop.
7. Serialize the rows up to ``max_response_bytes`` (:mod:`pgwarden.db.serialize`).
8. Always ``ROLLBACK`` (``Transaction.rollback()``), even on success: the
   read path never commits.

Steps 3-7 run under a client-side safety timeout, `_SAFETY_MARGIN_S` above
`statement_timeout`. It exists only for the case the server-side timeout
cannot cover -- a connection that never hears back at all -- and when it
fires the connection is abandoned (`terminate()`), never rolled back and
reused, since asyncpg does not guarantee a connection is usable after a
cancelled operation.

SAFETY: user SQL (the ``sql`` parameter) must only ever reach Postgres
through ``conn.prepare(sql)`` below, the extended protocol's Parse step.
Never call ``conn.execute()``/``.fetch()``/``.fetchval()``/``.fetchrow()``
directly on ``sql`` or on anything derived from it: ``execute()`` called
with no bound arguments uses the simple query protocol, which accepts
several semicolon-separated statements and would defeat the multi-statement
rejection above entirely (the public MCP-server bypass this product exists
to close -- see the spec's "Guarantees built outside the database get
bypassed"). Every other ``conn.execute()``/``.execute()`` call in this
module runs pgwarden's own fixed SQL text with bound parameters, never
``sql``. ``tests/unit/test_readpath_guard.py`` greps this module (and
``pools.py``) to enforce this statically.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import secrets
from typing import Any

import asyncpg

from pgwarden.db.errors import QueryError, RetryableDbError
from pgwarden.db.params import coerce_params
from pgwarden.db.pools import PoolManager
from pgwarden.db.serialize import Column, serialize_rows

# The exact text from spec item 5 step 3. Never interpolate values into
# this string; they are always bound as $1..$4.
_SET_CONFIG_SQL = (
    "SELECT set_config('statement_timeout', $1, true), "
    "set_config('lock_timeout', $2, true), "
    "set_config('idle_in_transaction_session_timeout', $3, true), "
    "set_config('application_name', $4, true)"
)

#: How far above `statement_timeout` the client-side safety timeout sits.
#: `statement_timeout` should always fire first; this is a last-resort
#: guard against a connection that never hears back at all (for example a
#: dead network path to the server), where the server-side timeout cannot
#: help because the server-side timer never got the chance to start.
_SAFETY_MARGIN_S = 2.0


@dataclasses.dataclass
class ReadConfig:
    """The subset of ``pgwarden.yaml``'s ``read:`` section this module needs.

    A plain dataclass rather than importing :class:`pgwarden.config.ReadConfig`
    directly, so this module has no dependency on the config/pydantic layer;
    callers pass ``ReadConfig(**config.read.model_dump())`` or build one by
    hand in tests.
    """

    statement_timeout_ms: int = 5000
    lock_timeout_ms: int = 1000
    idle_in_transaction_timeout_ms: int = 10000
    row_cap: int = 500
    max_response_bytes: int = 1_048_576


@dataclasses.dataclass
class ReadResult:
    """The outcome of one `query` call.

    On success, ``error`` is ``None`` and ``rows`` holds up to
    ``row_cap`` JSON-safe row objects. ``truncated`` means the row cap was
    hit (more rows exist than were fetched at all); ``bytes_truncated``
    means the byte cap dropped some of the rows that *were* fetched
    (including, in the extreme, every row -- see ``serialize.py``'s
    "oversized row" note). ``row_count`` is always ``len(rows)``: how many
    rows are actually present in this result.
    """

    columns: list[Column]
    rows: list[dict[str, Any]]
    row_count: int
    truncated: bool
    bytes_truncated: bool
    error: QueryError | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def statement_name() -> str:
    """A unique name for a user statement's server-side prepared statement.

    User SQL is never prepared as the *unnamed* statement: with the statement
    cache off, asyncpg also runs its own type-introspection query (for a result
    type it has not seen yet, such as an array) through the unnamed statement,
    which would replace the user's statement between Parse and Bind. A named
    statement is immune; the release-time ``DISCARD ALL`` deallocates it.
    """
    return f"pgw_{secrets.token_hex(8)}"


def default_application_name(role_name: str) -> str:
    return f"pgwarden:{role_name}"


def _query_error_from_postgres(exc: asyncpg.PostgresError) -> QueryError:
    sqlstate = exc.sqlstate or ""
    retryable = sqlstate == "53300"
    return QueryError(
        sqlstate=sqlstate,
        message=exc.args[0] if exc.args else str(exc),
        detail=getattr(exc, "detail", None),
        hint=getattr(exc, "hint", None),
        retryable=retryable,
        retry_after_s=1.0 if retryable else None,
    )


def _query_error_from_interface(exc: Exception) -> QueryError:
    # A client-side protocol/usage error (for example a bound-parameter
    # count mismatch): asyncpg raises these without a Postgres SQLSTATE.
    return QueryError(sqlstate="", message=str(exc))


async def run_read_query(
    pool_manager: PoolManager,
    role_name: str,
    sql: str,
    params: list[Any],
    *,
    config: ReadConfig | None = None,
    application_name: str | None = None,
) -> ReadResult:
    """Run ``sql`` (with ``params``) as ``role_name``, following the read path exactly."""
    cfg = config or ReadConfig()
    app_name = application_name or default_application_name(role_name)

    try:
        async with pool_manager.acquire(role_name) as conn:
            return await _run_on_connection(conn, sql, params, cfg, app_name)
    except RetryableDbError as exc:
        return ReadResult(
            columns=[],
            rows=[],
            row_count=0,
            truncated=False,
            bytes_truncated=False,
            error=QueryError(
                sqlstate=exc.sqlstate,
                message=str(exc),
                retryable=True,
                retry_after_s=exc.retry_after_s,
            ),
        )


async def _run_on_connection(
    conn: asyncpg.Connection,
    sql: str,
    params: list[Any],
    cfg: ReadConfig,
    app_name: str,
) -> ReadResult:
    tx = conn.transaction(isolation="repeatable_read", readonly=True)
    try:
        await tx.start()
    except asyncpg.PostgresError as exc:
        # BEGIN itself failed (a broken connection, not user input -- the
        # text is fixed). Nothing to roll back; the pool's own reset step
        # will find and discard a connection that cannot even BEGIN.
        return _error_result(_query_error_from_postgres(exc))

    safety_timeout_s = cfg.statement_timeout_ms / 1000.0 + _SAFETY_MARGIN_S
    abandoned = False
    try:
        return await asyncio.wait_for(
            _do_steps(conn, sql, params, cfg, app_name), timeout=safety_timeout_s
        )
    except TimeoutError:
        # `statement_timeout` should always fire first and surface as a
        # normal 57014 QueryCanceledError below; reaching this means the
        # connection never heard back at all. asyncpg does not guarantee a
        # connection is left in a usable state after a cancelled operation,
        # so it is abandoned outright (terminate(), no attempted ROLLBACK)
        # rather than rolled back and returned to the pool.
        abandoned = True
        conn.terminate()
        return _error_result(
            QueryError(
                sqlstate="",
                message=f"query did not complete within the {safety_timeout_s:.1f}s "
                "client-side safety timeout",
            )
        )
    except asyncpg.PostgresError as exc:
        return _error_result(_query_error_from_postgres(exc))
    except asyncpg.exceptions.InterfaceError as exc:
        return _error_result(_query_error_from_interface(exc))
    finally:
        # Always ROLLBACK -- the read path never commits, regardless of
        # what the user statement was (including a user statement whose
        # entire text is literally "COMMIT": that ends the transaction
        # early, and this ROLLBACK becomes a documented no-op on an
        # already-closed transaction rather than an error).
        # tx.start() never completed (BEGIN failed, handled above) or the
        # transaction already ended itself in a way asyncpg's own
        # Transaction bookkeeping does not expect; nothing left to do.
        if not abandoned:
            with contextlib.suppress(asyncpg.exceptions.InterfaceError):
                await tx.rollback()


async def _do_steps(
    conn: asyncpg.Connection, sql: str, params: list[Any], cfg: ReadConfig, app_name: str
) -> ReadResult:
    # pgwarden's own fixed SQL text with bound values -- never `sql`.
    await conn.execute(
        _SET_CONFIG_SQL,
        str(cfg.statement_timeout_ms),
        str(cfg.lock_timeout_ms),
        str(cfg.idle_in_transaction_timeout_ms),
        app_name,
    )

    # Extended protocol Parse. Rejects a second statement with 42601;
    # never conn.execute()/fetch() on `sql` (see the module guard).
    stmt = await conn.prepare(sql, name=statement_name())

    param_types = stmt.get_parameters()
    coerced = coerce_params(params, param_types)

    columns = [Column(name=a.name, type=a.type.name) for a in stmt.get_attributes()]

    cursor = await stmt.cursor(*coerced)
    fetched = await cursor.fetch(cfg.row_cap + 1)
    truncated = len(fetched) > cfg.row_cap
    if truncated:
        fetched = fetched[: cfg.row_cap]

    rows, bytes_truncated = serialize_rows(fetched, columns, cfg.max_response_bytes)
    return ReadResult(
        columns=columns,
        rows=rows,
        row_count=len(rows),
        truncated=truncated,
        bytes_truncated=bytes_truncated,
    )


def _error_result(error: QueryError) -> ReadResult:
    return ReadResult(
        columns=[], rows=[], row_count=0, truncated=False, bytes_truncated=False, error=error
    )


__all__ = ["ReadConfig", "ReadResult", "default_application_name", "run_read_query"]
