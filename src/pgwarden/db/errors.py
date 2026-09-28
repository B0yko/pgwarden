"""Typed errors shared by the connection pool and the read path.

Both :mod:`pgwarden.db.pools` and :mod:`pgwarden.db.readpath` need to hand
callers a structured error shape instead of a raw exception, so a later MCP
tool layer can return ``{"sqlstate", "message", "detail", "hint",
"retryable", "retry_after_s"}`` without re-parsing anything.
"""

from __future__ import annotations

import dataclasses

#: SQLSTATE Postgres itself uses for "too many connections" (role
#: CONNECTION LIMIT or server max_connections exhausted). Reused here for
#: pgwarden's own pool/global-cap exhaustion too, since from a caller's
#: point of view both are the same "no connection available, retry
#: shortly" condition (see :mod:`pgwarden.db.pools`).
TOO_MANY_CONNECTIONS_SQLSTATE = "53300"

#: Default backoff hint handed to callers of a retryable error, in seconds.
DEFAULT_RETRY_AFTER_S = 1.0


class RetryableDbError(RuntimeError):
    """A typed, retryable database-layer error.

    Raised by :mod:`pgwarden.db.pools` when no connection can be handed out
    right now (SQLSTATE 53300 from Postgres itself, or pgwarden's own
    per-principal/global pool capacity exhausted with nothing idle left to
    evict). Carries ``retry_after_s`` so a caller does not have to parse the
    message text to build a retryable tool error.
    """

    def __init__(self, message: str, *, sqlstate: str, retry_after_s: float) -> None:
        super().__init__(message)
        self.sqlstate = sqlstate
        self.retry_after_s = retry_after_s


@dataclasses.dataclass(frozen=True)
class QueryError:
    """The error half of a read-path result (see :class:`pgwarden.db.readpath.ReadResult`)."""

    sqlstate: str
    message: str
    detail: str | None = None
    hint: str | None = None
    retryable: bool = False
    retry_after_s: float | None = None


__all__ = [
    "DEFAULT_RETRY_AFTER_S",
    "TOO_MANY_CONNECTIONS_SQLSTATE",
    "QueryError",
    "RetryableDbError",
]
