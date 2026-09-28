"""The connection type state-database helpers accept: a plain asyncpg connection
or one checked out of an asyncpg pool (both expose the same query methods)."""

from __future__ import annotations

from typing import Any

import asyncpg
import asyncpg.pool

type AnyConn = asyncpg.Connection[Any] | asyncpg.pool.PoolConnectionProxy[Any]

__all__ = ["AnyConn"]
