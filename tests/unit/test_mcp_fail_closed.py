"""The MCP layer's fail-closed audit contract (no Postgres needed).

Every tool result passes through ``_audit_fail_closed``: when the audit insert
fails, the caller must return the error dict instead of any data. The state
layer's own AuditError raising is tested in tests/integration/test_audit.py;
this pins the MCP layer's half of the contract.
"""

from __future__ import annotations

import datetime as dt
from types import SimpleNamespace
from typing import Any

import pytest

from pgwarden import mcp_server
from pgwarden.identity import Principal
from pgwarden.state.audit import AuditError


class _FakePool:
    def acquire(self) -> _FakePool:
        return self

    async def __aenter__(self) -> object:
        return object()

    async def __aexit__(self, *exc: object) -> None:
        return None


class _FakeDeps:
    def require_state_pool(self) -> _FakePool:
        return _FakePool()


def _principal() -> Principal:
    return Principal(
        kind="person",
        subject="person:alice",
        role_name="pw_u_alice",
        email="alice@example.com",
        bundles=("read_all",),
        writer=None,
        masked=True,
        queries_per_minute=60,
        proposals_per_hour=10,
    )


def _ctx() -> Any:
    # No Starlette request: timing is absent, request id is generated,
    # client id is None -- the wrapper must work without a request object.
    return SimpleNamespace(request_context=SimpleNamespace(request=None))


async def test_audit_failure_returns_error_instead_of_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def broken_record(*args: Any, **kwargs: Any) -> None:
        raise AuditError("hash chain insert failed")

    monkeypatch.setattr(mcp_server.audit, "record", broken_record)
    data = {"rows_untrusted": [{"secret": "canary"}], "row_count": 1}
    out = await mcp_server._audit_fail_closed(
        _FakeDeps(),
        _principal(),
        _ctx(),
        tool="query",
        outcome="ok",
        sql_text="SELECT 1",
        rows_returned=1,
        result=data,
    )
    assert out is not None
    assert "fail-closed" in out["error"]["message"]
    assert "rows_untrusted" not in out  # no data may leak through the error


async def test_audit_success_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[dict[str, Any]] = []

    async def ok_record(*args: Any, **kwargs: Any) -> None:
        seen.append(kwargs)

    monkeypatch.setattr(mcp_server.audit, "record", ok_record)
    out = await mcp_server._audit_fail_closed(
        _FakeDeps(),
        _principal(),
        _ctx(),
        tool="query",
        outcome="ok",
        sql_text="SELECT 1",
        rows_returned=1,
        duration_ms=2,
        result={"rows_untrusted": []},
    )
    assert out is None
    assert seen and seen[0]["event"] == "tool_call"
    assert seen[0]["pg_role"] == "pw_u_alice"
    assert seen[0]["tool"] == "query"


async def test_uninitialised_state_pool_is_loud() -> None:
    deps = mcp_server.GatewayDeps(
        config=None,  # type: ignore[arg-type]  # never reached: the pool check fires first
        pool_manager=None,  # type: ignore[arg-type]
        state_dsn="postgresql://unused",
        read_config=mcp_server.ReadConfig(),
        now=lambda: dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
        state_pool=None,
    )
    with pytest.raises(RuntimeError, match="state pool is not initialised"):
        await mcp_server._audit_fail_closed(
            deps, _principal(), _ctx(), tool="whoami", outcome="ok"
        )
