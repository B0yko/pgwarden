"""A per-principal connection manager (deliberately not ``asyncpg.Pool``).

Each Postgres login role (a person's ``pw_u_<role>`` or a machine's
``pw_m_<role>``) gets its own small pool: a hard cap of ``max_size``
connections, connections idle longer than ``idle_timeout_s`` are closed, a
connection is recycled past ``max_lifetime_s`` regardless of use, and a
``global_cap`` across every principal's pools is enforced by evicting the
least-recently-used *idle* connection to make room (never a connection that
is actively in use).

``asyncpg.Pool`` was not used here because none of the above -- per-role
identity, the global cap with cross-pool LRU eviction, or the fixed
``DISCARD ALL`` reset on release (see ``_RESET_SQL`` below) -- is something
its own pool/reset model exposes; the lifetime, idle and hygiene rules need
to be explicit and independently testable (see ``tests/integration``).

Every physical connection is opened with ``statement_cache_size=0``.
Without it, asyncpg's own statement cache holds server-side prepared
statements by name across queries; user SQL running ``DISCARD ALL`` or
``DEALLOCATE ALL`` (which the read path's own reset also runs on release)
deallocates those same names server-side and breaks the cache --
``asyncpg.exceptions.InvalidSQLStatementNameError`` on the very next cached
query on that connection (verified by experiment; asyncpg's own error
message points at this exact fix). With ``statement_cache_size=0`` asyncpg
deallocates each statement itself immediately after use, so there is
nothing left for an errant ``DISCARD ALL``/``DEALLOCATE ALL`` to break.

On release, :meth:`PoolManager.acquire` runs a fixed reset *outside* any
transaction: ``DISCARD ALL``. Verified by experiment (see
``tests/integration/test_pools.py``) that, with ``statement_cache_size=0``,
a connection that has gone through ``PREPARE``, ``DEALLOCATE ALL``,
``LISTEN``, a ``WITH HOLD`` cursor, a non-local ``SET``/``set_config`` and a
session advisory lock is, after ``DISCARD ALL``, indistinguishable from a
brand-new connection in ``pg_prepared_statements``, ``pg_cursors``,
``pg_listening_channels()``, held advisory locks, ``current_user``,
``search_path`` and ``default_transaction_read_only`` -- and the next query
on it succeeds. If the reset itself fails for any reason, or the connection
is still in a transaction (the read/write paths never release one that
way), the connection is closed instead of returned to the pool -- a broken
or mid-transaction connection must never be handed to the next caller.

Idle/expired connections are reaped opportunistically on every
:meth:`PoolManager.acquire`, and also by a background task started with
:meth:`PoolManager.start` and stopped cleanly by :meth:`PoolManager.aclose`,
so a role that stops being used still has its idle connections closed
without needing another caller to trigger it. :meth:`PoolManager.close_role`
drops a role's idle connections immediately, when a person is suspended.
The wall clock is injectable (``clock=``) so idle/lifetime/eviction
behaviour is testable without real sleeps.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import time
from collections.abc import AsyncIterator, Callable
from urllib.parse import quote, urlsplit, urlunsplit

import asyncpg

from pgwarden.db.errors import (
    DEFAULT_RETRY_AFTER_S,
    TOO_MANY_CONNECTIONS_SQLSTATE,
    RetryableDbError,
)
from pgwarden.db.scram import derive_password

# Cannot run inside a transaction block; the read path always releases a
# connection with no transaction open (it ROLLBACKs before returning it),
# and this runs as its own implicit-transaction statement.
_RESET_SQL = "DISCARD ALL"

_CONNECT_TIMEOUT_S = 10.0
_RESET_TIMEOUT_S = 5.0


def _connect_dsn(target_dsn: str, role: str, password: str) -> str:
    """The target DSN (host/port/db/sslmode only) with ``role``'s credentials.

    Keeps the query string (``sslmode`` and anything else) from
    ``target_dsn`` untouched, so ``sslmode=disable`` (the demo) or the
    ``verify-full`` default both pass straight through.
    """
    parts = urlsplit(target_dsn)
    host = parts.hostname or "localhost"
    port = f":{parts.port}" if parts.port else ""
    netloc = f"{quote(role, safe='')}:{quote(password, safe='')}@{host}{port}"
    return urlunsplit((parts.scheme or "postgresql", netloc, parts.path, parts.query, ""))


@dataclasses.dataclass
class _PooledConn:
    conn: asyncpg.Connection
    created_at: float
    last_used_at: float


class _PrincipalPool:
    __slots__ = ("idle", "in_use", "last_activity", "role_name")

    def __init__(self, role_name: str) -> None:
        self.role_name = role_name
        self.idle: list[_PooledConn] = []
        self.in_use = 0
        # Overwritten by the manager's own clock on first checkout; this
        # default only matters before that ever happens.
        self.last_activity = 0.0

    @property
    def total(self) -> int:
        return len(self.idle) + self.in_use


class PoolManager:
    """Owns one :class:`_PrincipalPool` per login role name.

    ``target_dsn`` is ``PGWARDEN_TARGET_DSN`` (host/port/database/sslmode,
    never user or password); ``role_secret`` is ``PGWARDEN_ROLE_SECRET``,
    used the same way :mod:`pgwarden.db.scram` derives it for provisioning.
    Callers pass the actual login role name (``pw_u_bob``,
    ``pw_m_nightly_report``) to :meth:`acquire`; mapping an MCP principal
    (``person:bob``) to that role name is the identity layer's job, not
    this module's.
    """

    def __init__(
        self,
        *,
        target_dsn: str,
        role_secret: str,
        max_size: int = 2,
        idle_timeout_s: float = 60,
        max_lifetime_s: float = 300,
        global_cap: int = 60,
        reap_interval_s: float = 5.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._target_dsn = target_dsn
        self._role_secret = role_secret
        self._max_size = max_size
        self._idle_timeout_s = idle_timeout_s
        self._max_lifetime_s = max_lifetime_s
        self._global_cap = global_cap
        self._reap_interval_s = reap_interval_s
        self._clock = clock
        self._pools: dict[str, _PrincipalPool] = {}
        self._lock = asyncio.Lock()
        self._reaper_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Start the background reaper task. Idempotent."""
        if self._reaper_task is None:
            self._reaper_task = asyncio.create_task(self._reap_loop())

    async def _reap_loop(self) -> None:
        while True:
            await asyncio.sleep(self._reap_interval_s)
            async with self._lock:
                await self._reap_locked()

    async def close_role(self, role_name: str) -> None:
        """Forcibly close every idle connection held for ``role_name`` (used for suspension).

        A connection currently checked out is not touched here (it is not
        safe to close from under whoever holds it); it is dropped instead
        of returned to the pool the next time it is released, because by
        then :meth:`_checkin` finds no pool left to put it back into.
        """
        async with self._lock:
            pool = self._pools.pop(role_name, None)
            if pool is None:
                return
            for pooled in pool.idle:
                with contextlib.suppress(Exception):
                    await pooled.conn.close()
            pool.idle = []

    @contextlib.asynccontextmanager
    async def acquire(self, role_name: str) -> AsyncIterator[asyncpg.Connection]:
        """Check a connection for ``role_name`` out, yield it, then release it.

        Raises :class:`~pgwarden.db.errors.RetryableDbError` (SQLSTATE
        53300) if no connection is available right now: the role's own
        Postgres ``CONNECTION LIMIT`` was hit while opening a new physical
        connection, this principal's own pool is already at ``max_size``,
        or the global cap is full with no idle connection anywhere left to
        evict. The MCP tool layer surfaces this as a retryable tool error
        with ``retry_after_s``.
        """
        pooled = await self._checkout(role_name)
        try:
            yield pooled.conn
        finally:
            await self._checkin(role_name, pooled)

    async def _checkout(self, role_name: str) -> _PooledConn:
        async with self._lock:
            await self._reap_locked()
            pool = self._pools.pop(role_name, None)
            if pool is None:
                pool = _PrincipalPool(role_name)
            # Re-insert last: dict order is this manager's LRU order, oldest
            # (least-recently-touched) principal first.
            self._pools[role_name] = pool
            pool.last_activity = self._clock()

            if pool.idle:
                pooled = pool.idle.pop()
                pool.in_use += 1
                return pooled

            if pool.total >= self._max_size:
                raise RetryableDbError(
                    f"pool for {role_name!r} is at its per-principal limit "
                    f"({self._max_size} connections)",
                    sqlstate=TOO_MANY_CONNECTIONS_SQLSTATE,
                    retry_after_s=DEFAULT_RETRY_AFTER_S,
                )

            at_global_cap = self._global_count_locked() >= self._global_cap
            if at_global_cap and not await self._evict_one_idle_locked(exclude=role_name):
                raise RetryableDbError(
                    f"global connection cap ({self._global_cap}) reached, nothing idle to evict",
                    sqlstate=TOO_MANY_CONNECTIONS_SQLSTATE,
                    retry_after_s=DEFAULT_RETRY_AFTER_S,
                )

            try:
                pooled = await self._open(role_name)
            except asyncpg.TooManyConnectionsError as exc:
                raise RetryableDbError(
                    str(exc),
                    sqlstate=TOO_MANY_CONNECTIONS_SQLSTATE,
                    retry_after_s=DEFAULT_RETRY_AFTER_S,
                ) from exc
            pool.in_use += 1
            return pooled

    async def _checkin(self, role_name: str, pooled: _PooledConn) -> None:
        reset_ok = await self._reset(pooled.conn)
        async with self._lock:
            pool = self._pools.get(role_name)
            if pool is not None:
                pool.in_use = max(0, pool.in_use - 1)
            now = self._clock()
            too_old = (now - pooled.created_at) > self._max_lifetime_s
            if pool is not None and reset_ok and not too_old and not pooled.conn.is_closed():
                pooled.last_used_at = now
                pool.idle.append(pooled)
                return
        if not pooled.conn.is_closed():
            with contextlib.suppress(Exception):
                await pooled.conn.close()

    async def _reset(self, conn: asyncpg.Connection) -> bool:
        if conn.is_closed():
            return False
        if conn.is_in_transaction():
            # The read path always ROLLBACKs before releasing a connection.
            # A connection still in a transaction here means something went
            # wrong upstream (or a future caller did not follow that
            # discipline); it is closed instead of reused, never rolled
            # back and put back into circulation.
            return False
        try:
            await conn.execute(_RESET_SQL, timeout=_RESET_TIMEOUT_S)
            return True
        except Exception:
            return False

    def _global_count_locked(self) -> int:
        return sum(p.total for p in self._pools.values())

    async def _evict_one_idle_locked(self, *, exclude: str) -> bool:
        for name, pool in self._pools.items():
            if name == exclude or not pool.idle:
                continue
            victim = pool.idle.pop(0)
            with contextlib.suppress(Exception):
                await victim.conn.close()
            return True
        return False

    async def _reap_locked(self) -> None:
        now = self._clock()
        empty: list[str] = []
        for name, pool in self._pools.items():
            keep: list[_PooledConn] = []
            for pooled in pool.idle:
                idle_for = now - pooled.last_used_at
                age = now - pooled.created_at
                if idle_for > self._idle_timeout_s or age > self._max_lifetime_s:
                    with contextlib.suppress(Exception):
                        await pooled.conn.close()
                else:
                    keep.append(pooled)
            pool.idle = keep
            if pool.total == 0:
                empty.append(name)
        for name in empty:
            del self._pools[name]

    async def _open(self, role_name: str) -> _PooledConn:
        password = derive_password(self._role_secret, role_name)
        dsn = _connect_dsn(self._target_dsn, role_name, password)
        conn = await asyncpg.connect(dsn, timeout=_CONNECT_TIMEOUT_S, statement_cache_size=0)
        now = self._clock()
        return _PooledConn(conn=conn, created_at=now, last_used_at=now)

    def stats(self) -> dict[str, tuple[int, int]]:
        """``{role_name: (idle, in_use)}`` for every principal pool that has been touched."""
        return {name: (len(p.idle), p.in_use) for name, p in self._pools.items()}

    async def aclose(self) -> None:
        """Stop the reaper task and best-effort close every idle connection."""
        task, self._reaper_task = self._reaper_task, None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        async with self._lock:
            for pool in self._pools.values():
                for pooled in pool.idle:
                    with contextlib.suppress(Exception):
                        await pooled.conn.close()
                pool.idle = []
            self._pools.clear()


__all__ = ["PoolManager"]
