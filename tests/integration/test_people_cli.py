"""`pgwarden people suspend|unsuspend|list` against the state database."""

from __future__ import annotations

import asyncio
from pathlib import Path

import asyncpg
import pytest
from typer.testing import CliRunner

from pgwarden.cli import app

pytestmark = pytest.mark.pg

REPO_ROOT = Path(__file__).parent.parent.parent


async def _suspended(state_dsn: str, role: str) -> bool:
    conn = await asyncpg.connect(state_dsn, timeout=5)
    try:
        return bool(
            await conn.fetchval(
                "SELECT suspended FROM pgwarden.people_status WHERE person_role = $1", role
            )
        )
    finally:
        await conn.close()


def test_suspend_list_unsuspend(pg_state_dsn: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PGWARDEN_CONFIG", str(REPO_ROOT / "demo" / "pgwarden.yaml"))
    monkeypatch.setenv("PGWARDEN_STATE_DSN", pg_state_dsn)
    runner = CliRunner()

    result = runner.invoke(app, ["people", "suspend", "dana@example.com"])
    assert result.exit_code == 0, result.output
    assert "suspended pw_u_dana" in result.output
    assert asyncio.run(_suspended(pg_state_dsn, "pw_u_dana"))

    listing = runner.invoke(app, ["people", "list"])
    assert listing.exit_code == 0
    assert any("pw_u_dana" in line and "suspended" in line for line in listing.output.splitlines())

    result = runner.invoke(app, ["people", "unsuspend", "dana"])
    assert result.exit_code == 0, result.output
    assert not asyncio.run(_suspended(pg_state_dsn, "pw_u_dana"))

    unknown = runner.invoke(app, ["people", "suspend", "nobody@example.com"])
    assert unknown.exit_code != 0
