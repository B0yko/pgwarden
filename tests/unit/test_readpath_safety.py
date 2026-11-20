"""Connection-level safety properties of the read path, with a fake connection.

The integration suite (tests/integration/test_readpath.py) proves the sequence
against a real Postgres; these pin the three failure behaviours that a real
server cannot be asked to produce on demand:

- the client-side safety timeout abandons the connection (terminate, no rollback);
- a successful read still rolls back -- the read path never commits;
- a failed BEGIN surfaces the SQLSTATE without touching the connection further.
"""

from __future__ import annotations

import asyncio
from typing import Any

import asyncpg
import pytest

from pgwarden.db import readpath
from pgwarden.db.readpath import ReadConfig, _run_on_connection


class _FakeTx:
    def __init__(self, *, begin_error: Exception | None = None) -> None:
        self.begin_error = begin_error
        self.started = False
        self.rolled_back = False
        self.committed = False

    async def start(self) -> None:
        if self.begin_error is not None:
            raise self.begin_error
        self.started = True

    async def rollback(self) -> None:
        self.rolled_back = True

    async def commit(self) -> None:  # pragma: no cover - the read path must never call it
        self.committed = True
        raise AssertionError("the read path must never commit")


class _FakeCursor:
    async def fetch(self, n: int) -> list[Any]:
        return []


class _FakeStmt:
    def get_parameters(self) -> list[Any]:
        return []

    def get_attributes(self) -> list[Any]:
        return []

    async def cursor(self, *params: Any) -> _FakeCursor:
        return _FakeCursor()


class _FakeConn:
    """Stands in for asyncpg.Connection: fixed SQL succeeds, user SQL hangs."""

    def __init__(self, tx: _FakeTx, *, hang: bool = False, interface_error: bool = False) -> None:
        self.tx = tx
        self.hang = hang
        self.interface_error = interface_error
        self.terminated = False
        self.executed: list[str] = []
        self.prepared: list[str] = []

    def transaction(self, **kwargs: Any) -> _FakeTx:
        assert kwargs.get("readonly") is True
        assert kwargs.get("isolation") == "repeatable_read"
        return self.tx

    async def execute(self, sql: str, *args: Any) -> None:
        self.executed.append(sql)

    async def prepare(self, sql: str, *, name: str) -> _FakeStmt:
        self.prepared.append(sql)
        if self.interface_error:
            raise asyncpg.exceptions.InterfaceError("a client-side protocol error")
        if self.hang:
            await asyncio.sleep(60)  # the safety timeout must fire long before this
        return _FakeStmt()

    def terminate(self) -> None:
        self.terminated = True


async def test_safety_timeout_abandons_the_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(readpath, "_SAFETY_MARGIN_S", 0.05)
    tx = _FakeTx()
    conn = _FakeConn(tx, hang=True)
    result = await _run_on_connection(
        conn, "SELECT 1", [], ReadConfig(statement_timeout_ms=1), "pgwarden:test"
    )
    assert result.error is not None
    assert "safety timeout" in result.error.message
    assert conn.terminated  # abandoned outright...
    assert not tx.rolled_back  # ...never rolled back and returned to the pool
    assert not tx.committed


async def test_success_still_rolls_back() -> None:
    tx = _FakeTx()
    conn = _FakeConn(tx)
    result = await _run_on_connection(conn, "SELECT 1", [], ReadConfig(), "pgwarden:test")
    assert result.ok
    assert tx.started and tx.rolled_back and not tx.committed
    assert not conn.terminated
    # the user statement went through prepare (extended protocol), never execute
    assert conn.prepared == ["SELECT 1"]
    assert all("SELECT 1" not in sql for sql in conn.executed)


async def test_interface_error_becomes_a_query_error_without_sqlstate() -> None:
    tx = _FakeTx()
    conn = _FakeConn(tx, interface_error=True)
    result = await _run_on_connection(conn, "SELECT $1", [], ReadConfig(), "pgwarden:test")
    assert result.error is not None
    assert result.error.sqlstate == ""
    assert "protocol error" in result.error.message
    assert tx.rolled_back and not conn.terminated


async def test_failed_begin_surfaces_sqlstate_and_stops() -> None:
    tx = _FakeTx(begin_error=asyncpg.exceptions.InvalidCatalogNameError("no such database"))
    conn = _FakeConn(tx)
    result = await _run_on_connection(conn, "SELECT 1", [], ReadConfig(), "pgwarden:test")
    assert result.error is not None
    assert result.error.sqlstate == "3D000"
    assert not conn.prepared  # nothing ran after the failed BEGIN
    assert not tx.rolled_back and not conn.terminated
